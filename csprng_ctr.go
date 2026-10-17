//go:build windows || linux

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// ctrRefreshInterval 抗泄漏 refresh 间隔（Generate 次数）
	ctrRefreshInterval = 1 << 16
	// ctrRefreshMaxTime 最长间隔时间
	ctrRefreshMaxTime = 60 * time.Second
	// ctrMixRefreshGap Mix 后触发 refresh 的最小间隔
	ctrMixRefreshGap = 1 * time.Second
)

// CTRDRBG 是 NIST SP 800-90A 的 CTR_DRBG（AES-256），
// 附加安全增强：
//   - 密钥分裂：k = k1 XOR k2
//   - 计数器递增恒定时间（无数据依赖分支）
//   - 定期 refresh：每 2^16 次 Generate 后从 Mix 池 + V 派生新密钥
//   - 前向保密：每次 Generate 后 update(nil)
type CTRDRBG struct {
	mu          sync.Mutex
	k1          [32]byte
	k2          [32]byte
	v           [16]byte
	block       cipher.Block // 缓存 AES，每次 deriveAndSplit 后重建
	refreshMat  [32]byte
	refreshCtr  uint64
	lastRefresh time.Time
	initialized bool

	totalBytes int64
	ratchets   int64
}

func NewCTRDRBG(seed []byte) (*CTRDRBG, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("CTR-DRBG 种子至少 32 字节，当前 %d", len(seed))
	}
	d := &CTRDRBG{}
	d.deriveAndSplit(seed)
	d.initialized = true
	d.lastRefresh = time.Now()
	secureZeroHard(seed)
	return d, nil
}

func (d *CTRDRBG) currentKey() [32]byte {
	var k [32]byte
	for i := 0; i < 32; i++ {
		k[i] = d.k1[i] ^ d.k2[i]
	}
	return k
}

// incrementV 恒定时间递增 V（无数据依赖分支）
func (d *CTRDRBG) incrementV() {
	var carry uint8 = 1
	for j := 15; j >= 0; j-- {
		sum := uint16(d.v[j]) + uint16(carry)
		d.v[j] = uint8(sum)
		carry = uint8(sum >> 8)
	}
}

func (d *CTRDRBG) generateInternal(out []byte) {
	for i := 0; i < len(out); i += 16 {
		d.incrementV()
		end := i + 16
		if end > len(out) {
			end = len(out)
		}
		d.block.Encrypt(out[i:end], d.v[:])
	}
}

func (d *CTRDRBG) deriveAndSplit(providedData []byte) {
	k := d.currentKey()
	b, err := aes.NewCipher(k[:])
	if err != nil {
		secureZeroHard(k[:])
		return
	}
	d.block = b
	secureZeroHard(k[:])

	temp := make([]byte, 48)
	d.generateInternal(temp)
	if len(providedData) > 0 {
		for i := 0; i < 48 && i < len(providedData); i++ {
			temp[i] ^= providedData[i]
		}
	}

	var newK [32]byte
	copy(newK[:], temp[:32])
	copy(d.v[:], temp[32:48])
	secureZeroHard(temp)

	// 分裂：k1 = sha256(newK || V || "split")，k2 = newK XOR k1
	h := sha256.New()
	h.Write(newK[:])
	h.Write(d.v[:])
	h.Write([]byte("ctr-split-v1"))
	var k1 [32]byte
	copy(k1[:], h.Sum(nil))

	subtle.ConstantTimeCopy(1, d.k1[:], k1[:])
	for i := 0; i < 32; i++ {
		d.k2[i] = newK[i] ^ k1[i]
	}

	// 用新密钥重建 block
	k = d.currentKey()
	b, err = aes.NewCipher(k[:])
	if err == nil {
		d.block = b
	} else {
		// 理论上 32 字节密钥不会失败，但保险起见置 nil，
		// 让 Generate 检查并拒绝输出，避免状态不一致
		d.block = nil
	}
	secureZeroHard(k[:])
	secureZeroHard(k1[:])
	secureZeroHard(newK[:])
}

func (d *CTRDRBG) update(providedData []byte) {
	d.deriveAndSplit(providedData)
}

func (d *CTRDRBG) refresh() {
	k := d.currentKey()
	h := sha256.New()
	h.Write([]byte("ctr-refresh-v1"))
	h.Write(k[:])
	h.Write(d.v[:])
	h.Write(d.refreshMat[:])
	refreshMat := h.Sum(nil)

	d.deriveAndSplit(refreshMat)

	secureZeroHard(k[:])
	secureZeroHard(refreshMat)
	secureZeroHard(d.refreshMat[:])
	d.refreshCtr = 0
	d.lastRefresh = time.Now()
	atomic.AddInt64(&d.ratchets, 1)
}

func (d *CTRDRBG) Generate(n int) []byte {
	if n <= 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.initialized {
		return nil
	}

	if d.block == nil {
		return nil
	}
	out := make([]byte, n)
	d.generateInternal(out)
	d.update(nil)

	d.refreshCtr++
	if d.refreshCtr >= ctrRefreshInterval || time.Since(d.lastRefresh) >= ctrRefreshMaxTime {
		d.refresh()
	}

	atomic.AddInt64(&d.totalBytes, int64(n))
	atomic.AddInt64(&d.ratchets, 1)
	return out
}

func (d *CTRDRBG) Mix(entropy []byte) {
	if len(entropy) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	h := sha256.New()
	h.Write(d.refreshMat[:])
	h.Write(entropy)
	copy(d.refreshMat[:], h.Sum(nil))

	if d.initialized {
		d.update(entropy)
	}

	if time.Since(d.lastRefresh) >= ctrMixRefreshGap {
		d.refresh()
	}
}

func (d *CTRDRBG) Stats() (int64, int64) {
	return atomic.LoadInt64(&d.totalBytes), atomic.LoadInt64(&d.ratchets)
}

func (d *CTRDRBG) Name() string {
	return "aes-256-ctr (NIST SP 800-90A, split-key + refresh)"
}
