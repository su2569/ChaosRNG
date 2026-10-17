//go:build windows || linux

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"sync"
	"sync/atomic"
	"time"
)

const ctrIVLen = 16

// ---------- HashStir ----------
type HashStir struct {
	mu           sync.Mutex
	algorithm    string
	totalStirred int
}

func (h *HashStir) Algorithm() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.algorithm
}

func (h *HashStir) TotalStirred() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.totalStirred
}

func NewHashStir(algo string) *HashStir {
	if algo != "sha512" {
		algo = "sha256"
	}
	return &HashStir{algorithm: algo}
}

func (h *HashStir) digest(data []byte) []byte {
	if h.algorithm == "sha512" {
		s := sha512.Sum512(data)
		return s[:32]
	}
	s := sha256.Sum256(data)
	return s[:]
}

func (h *HashStir) Stir(data []byte) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.totalStirred += len(data)
	ts := safeTimestampBytes()
	buf := make([]byte, 0, len(data)+len(ts))
	buf = append(buf, data...)
	buf = append(buf, ts...)
	res := h.digest(buf)
	secureZero(buf)
	return res
}

func (h *HashStir) StirMultiple(chunks [][]byte) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	h.totalStirred += total
	buf := make([]byte, 0, total+16)
	for _, c := range chunks {
		buf = append(buf, c...)
	}
	buf = append(buf, safeTimestampBytes()...)
	res := h.digest(buf)
	secureZero(buf)
	return res
}

// ---------- ChaosEntropyPool（新增 atomic 快照） ----------
type ChaosEntropyPool struct {
	mu        sync.Mutex
	acc       [sha256.Size]byte
	events    int
	lastMix   time.Time
	createdAt time.Time
	stirrer   *HashStir
	snapshot  atomic.Value // 存 [sha256.Size]byte，供无锁读
	drbg      DRBG         // 可插拔 CSPRNG 后端（system/hmac/ctr/none），nil 表示旧逻辑
}

func NewChaosEntropyPool(stirrer *HashStir) *ChaosEntropyPool {
	p := &ChaosEntropyPool{createdAt: time.Now(), stirrer: stirrer}
	// 初始化快照，避免 Load 返回 nil
	var zero [sha256.Size]byte
	p.snapshot.Store(zero)
	return p
}

func (p *ChaosEntropyPool) mixRaw(b []byte) {
	h := sha256.New()
	p.mu.Lock()
	h.Write(p.acc[:])
	h.Write(b)
	var newAcc [sha256.Size]byte
	copy(newAcc[:], h.Sum(nil))
	p.acc = newAcc
	p.events++
	p.lastMix = time.Now()
	p.mu.Unlock()

	// 无锁更新快照（性能关键路径）
	p.snapshot.Store(newAcc)
}

func (p *ChaosEntropyPool) MixEvent(s string) { p.mixRaw([]byte(s)) }
func (p *ChaosEntropyPool) MixBytes(b []byte) { p.mixRaw(p.stirrer.Stir(b)) }

// MixBytesFiltered 先做纯度筛选再混池：
//
//	purity <  30%      -> 拒绝
//	purity ∈ [30%,90%) -> 有损压缩后混入
//	purity ≥  90%      -> 直接混入
//
// 短于 32 字节的样本统计不可靠，直接混入。
func (p *ChaosEntropyPool) MixBytesFiltered(b []byte) bool {
	if len(b) >= purityMinBytes {
		rejectBelow, highEnough := purityThresholds(len(b))
		purity := ComputePurity(b)
		if purity < rejectBelow {
			return false
		}
		if purity < highEnough {
			cond := CondenseEntropy(b)
			if len(cond) == 0 {
				return false
			}
			p.MixBytes(cond)
			if p.drbg != nil {
				p.drbg.Mix(cond)
			}
			secureZero(cond)
			return true
		}
	}
	p.MixBytes(b)
	if p.drbg != nil {
		p.drbg.Mix(b)
	}
	return true
}

// DigestFast 无锁读池摘要（供批量生成路径使用）
func (p *ChaosEntropyPool) DigestFast() [sha256.Size]byte {
	if v := p.snapshot.Load(); v != nil {
		return v.([sha256.Size]byte)
	}
	p.mu.Lock()
	acc := p.acc
	p.mu.Unlock()
	p.snapshot.Store(acc)
	return acc
}

// Digest 保持原有接口兼容
func (p *ChaosEntropyPool) Digest() []byte {
	a := p.DigestFast()
	out := make([]byte, sha256.Size)
	copy(out, a[:])
	return out
}

func (p *ChaosEntropyPool) EventCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.events
}

// ---------- SeedGenerator（新增批量版本） ----------
// GenerateSeed 保持兼容（单个）
func GenerateSeed(pool *ChaosEntropyPool) []byte {
	s := GenerateSeeds(pool, 1)
	return s
}

// GenerateSeeds 批量生成 n 个种子（n*32 字节）
// 优化：1 次系统熵 + 1 次池快照 + 1 次时间戳哈希
func GenerateSeeds(pool *ChaosEntropyPool, n int) []byte {
	if n <= 0 {
		return nil
	}
	total := n * 32

	// DRBG 模式：全部输出由选定 CSPRNG 后端产生
	// system: SystemDRBG -> crypto/rand
	// hmac:   HMAC-DRBG（纯软件，NIST SP 800-90A）
	// ctr:    CTR-DRBG（纯软件，AES-NI 加速）
	// none:   PhysicalDRBG（纯物理熵）
	if pool.drbg != nil {
		raw := pool.drbg.Generate(total)
		if raw == nil || len(raw) != total {
			return nil
		}
		// 只有 system 后端需要额外混入池摘要
		// 原因：
		//   - system.Mix 是空操作 → 必须在这里 XOR 让池熵参与输出
		//   - hmac/ctr/mixed 的 Mix 已经立即 update(entropy) → DRBG 内部吸收了池熵
		//   - 再 XOR d[i%32]（周期 32 字节）会强化 d 的微弱偏差，
		//     导致 GM/T 二元推导检测（bit 距离 256）敏感项失败
		// 用类型判断而非字符串比较，避免 Name() 改文本时静默失效
		if _, isSystem := pool.drbg.(*SystemDRBG); isSystem {
			d := pool.DigestFast()
			for i := 0; i < total; i++ {
				raw[i] ^= d[i%32]
			}
		}
		return raw
	}

	// 旧行为：osRandom XOR 池快照 XOR 时间戳
	sys := osRandom(total)
	d := pool.DigestFast()
	ts := sha256.Sum256(safeTimestampBytes())

	out := make([]byte, total)
	for i := 0; i < n; i++ {
		base := i * 32
		for j := 0; j < 32; j++ {
			out[base+j] = sys[base+j] ^ d[j] ^ ts[j]
		}
	}
	secureZero(sys)
	return out
}

// ---------- 冯·诺依曼纠偏 ----------
func VonNeumann(data []byte) []byte {
	bits := make([]uint8, 0, len(data)*8)
	for _, by := range data {
		for k := 7; k >= 0; k-- {
			bits = append(bits, (by>>uint(k))&1)
		}
	}
	outBits := make([]uint8, 0, len(bits)/4)
	for i := 0; i+1 < len(bits); {
		a, b := bits[i], bits[i+1]
		if a == 0 && b == 1 {
			outBits = append(outBits, 0)
		} else if a == 1 && b == 0 {
			outBits = append(outBits, 1)
		}
		i += 2
	}
	out := make([]byte, (len(outBits)+7)/8)
	for i, bt := range outBits {
		if bt == 1 {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}

// ---------- 综合密钥派生 ----------
func deriveAESKey(pool *ChaosEntropyPool) []byte {
	sys := osRandom(32)
	d := pool.Digest()
	h := sha256.New()
	h.Write(sys)
	h.Write(d)
	key := h.Sum(nil)
	secureZero(sys)
	return key
}

// ---------- AES-256-CTR ----------
func aes256CTR(key, iv, plaintext []byte) []byte {
	if len(key) != 32 || len(iv) != ctrIVLen {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(out, plaintext)
	return out
}
