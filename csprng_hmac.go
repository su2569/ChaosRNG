//go:build windows || linux

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	hmacRefreshInterval = 1 << 16
	hmacRefreshMaxTime  = 60 * time.Second
	hmacMixRefreshGap   = 1 * time.Second
)

// HMACDRBG 是 NIST SP 800-90A 的 HMAC_DRBG（SHA-256），附加安全增强：
//   - 密钥分裂：k = k1 XOR k2
//   - 定期 refresh：每 2^16 次 Generate 或 60s 空闲后刷新
//   - Mix 后节流 refresh：外部熵注入后 1s 内触发
//   - 前向保密：每次 Generate 后 update(nil) 销毁旧状态
type HMACDRBG struct {
	mu          sync.Mutex
	k1          [32]byte
	k2          [32]byte
	v           [32]byte
	refreshMat  [32]byte
	refreshCtr  uint64
	lastRefresh time.Time
	initialized bool

	totalBytes int64
	ratchets   int64
}

func NewHMACDRBG(seed []byte) (*HMACDRBG, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("HMAC-DRBG 种子至少 32 字节，当前 %d", len(seed))
	}
	d := &HMACDRBG{}
	for i := range d.v {
		d.v[i] = 0x01
	}
	d.deriveAndSplit(seed)
	d.initialized = true
	d.lastRefresh = time.Now()
	secureZeroHard(seed)
	return d, nil
}

func (d *HMACDRBG) currentKey() [32]byte {
	var k [32]byte
	for i := 0; i < 32; i++ {
		k[i] = d.k1[i] ^ d.k2[i]
	}
	return k
}

func (d *HMACDRBG) deriveAndSplit(providedData []byte) {
	k := d.currentKey()

	h := hmac.New(sha256.New, k[:])
	h.Write(d.v[:])
	h.Write([]byte{0x00})
	if len(providedData) > 0 {
		h.Write(providedData)
	}
	newK := h.Sum(nil)

	h = hmac.New(sha256.New, newK)
	h.Write(d.v[:])
	copy(d.v[:], h.Sum(nil))

	if len(providedData) > 0 {
		h = hmac.New(sha256.New, newK)
		h.Write(d.v[:])
		h.Write([]byte{0x01})
		h.Write(providedData)
		newK = h.Sum(nil)

		h = hmac.New(sha256.New, newK)
		h.Write(d.v[:])
		copy(d.v[:], h.Sum(nil))
	}

	h = hmac.New(sha256.New, newK)
	h.Write([]byte("hmac-split-v1"))
	h.Write(d.v[:])
	var k1 [32]byte
	copy(k1[:], h.Sum(nil))

	subtle.ConstantTimeCopy(1, d.k1[:], k1[:])
	for i := 0; i < 32; i++ {
		d.k2[i] = newK[i] ^ k1[i]
	}

	secureZeroHard(k[:])
	secureZeroHard(newK)
	secureZeroHard(k1[:])
}

func (d *HMACDRBG) update(providedData []byte) {
	d.deriveAndSplit(providedData)
}

func (d *HMACDRBG) refresh() {
	k := d.currentKey()
	h := hmac.New(sha256.New, k[:])
	h.Write(d.v[:])
	h.Write(d.refreshMat[:])
	h.Write([]byte("hmac-refresh-v1"))
	refreshMat := h.Sum(nil)

	d.deriveAndSplit(refreshMat)

	secureZeroHard(k[:])
	secureZeroHard(refreshMat)
	secureZeroHard(d.refreshMat[:])
	d.refreshCtr = 0
	d.lastRefresh = time.Now()
	atomic.AddInt64(&d.ratchets, 1)
}

// Generate 输出 n 字节。
//
// 性能说明：内层循环不清零临时 V（下次迭代被覆盖，且已作为输出的一部分公开），
// 避免每次 RtlSecureZeroMemory 的 20~30μs 开销（Generate(32768) 需 1024 次）。
// 真正的密钥 K 在循环外用 secureZeroHard 清除。
func (d *HMACDRBG) Generate(n int) []byte {
	if n <= 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.initialized {
		return nil
	}

	k := d.currentKey()
	out := make([]byte, n)
	h := hmac.New(sha256.New, k[:])
	pos := 0
	for pos < n {
		h.Reset()
		h.Write(d.v[:])
		v := h.Sum(nil)
		copy(d.v[:], v)
		pos += copy(out[pos:], v)
		// 不清零临时 v：性能关键路径
	}
	secureZeroHard(k[:])

	// 前向保密
	d.update(nil)

	// 抗泄漏：次数或时间任一触发 refresh
	d.refreshCtr++
	if d.refreshCtr >= hmacRefreshInterval || time.Since(d.lastRefresh) >= hmacRefreshMaxTime {
		d.refresh()
	}

	atomic.AddInt64(&d.totalBytes, int64(n))
	atomic.AddInt64(&d.ratchets, 1)
	return out
}

func (d *HMACDRBG) Mix(entropy []byte) {
	if len(entropy) == 0 {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	h := hmac.New(sha256.New, d.refreshMat[:])
	h.Write(entropy)
	copy(d.refreshMat[:], h.Sum(nil))

	if d.initialized {
		d.update(entropy)
	}

	if time.Since(d.lastRefresh) >= hmacMixRefreshGap {
		d.refresh()
	}
}

func (d *HMACDRBG) Stats() (int64, int64) {
	return atomic.LoadInt64(&d.totalBytes), atomic.LoadInt64(&d.ratchets)
}

func (d *HMACDRBG) Name() string {
	return "hmac-sha256 (NIST SP 800-90A, split-key + refresh)"
}
