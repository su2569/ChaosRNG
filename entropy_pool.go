//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"sync"
	"time"
)

const ctrIVLen = 16 // AES 块大小 = CTR 计数器长度

// ---------- HashStir（保持不变） ----------
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

// ---------- ChaosEntropyPool（保持不变） ----------
type ChaosEntropyPool struct {
	mu        sync.Mutex
	acc       [sha256.Size]byte
	events    int
	lastMix   time.Time
	createdAt time.Time
	stirrer   *HashStir
}

func NewChaosEntropyPool(stirrer *HashStir) *ChaosEntropyPool {
	return &ChaosEntropyPool{createdAt: time.Now(), stirrer: stirrer}
}

func (p *ChaosEntropyPool) mixRaw(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := sha256.New()
	h.Write(p.acc[:])
	h.Write(b)
	copy(p.acc[:], h.Sum(nil))
	p.events++
	p.lastMix = time.Now()
}

func (p *ChaosEntropyPool) MixEvent(s string) { p.mixRaw([]byte(s)) }
func (p *ChaosEntropyPool) MixBytes(b []byte) { p.mixRaw(p.stirrer.Stir(b)) }

func (p *ChaosEntropyPool) Digest() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, sha256.Size)
	copy(out, p.acc[:])
	return out
}

func (p *ChaosEntropyPool) EventCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.events
}

// ---------- SeedGenerator（保持不变） ----------
func GenerateSeed(pool *ChaosEntropyPool) []byte {
	r := osRandom(32)
	d := pool.Digest()
	th := sha256.Sum256(safeTimestampBytes())
	seed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		seed[i] = r[i] ^ d[i] ^ th[i]
	}
	secureZero(r)
	return seed
}

// ---------- 冯·诺依曼纠偏（保持不变） ----------
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
// deriveAESKey: AES-256 密钥 = SHA256( 系统熵(osRandom 32B) || 熵池摘要(32B) )
//   - 系统熵保证多实例密钥互不相关（即使池状态几乎相同）；
//   - 熵池摘要把当前池状态绑进密钥，池一旦被新熵源搅动，重派生的密钥就不同；
//   - 输出固定 32 字节，天然满足 AES-256 要求。
// 调用方负责在生命周期结束时 secureZero 返回的 key。
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

// ---------- AES-256-CTR（替代原 AES-256-ECB） ----------
// 特性：
//   - 流模式：无填充、密文长度 == 明文长度；
//   - CTR 每个 16B 块独立，天然可并行；Go 标准库底层走 AES-NI，
//     指令级并行已经吃满；
//   - 调用方必须为同一密钥传入不重复的 iv（推荐 osRandom(ctrIVLen)），
//     否则密钥流复用会泄漏 XOR 关系。
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