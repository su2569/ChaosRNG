//go:build windows || linux || darwin

package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
)

// MixedDRBG 混合 HMAC-SHA256 DRBG 和 AES-256-CTR DRBG：
// 两者的输出 XOR 混合。
//
// 安全属性：
//   - 备份安全：只要其中一个 DRBG 安全，输出就安全
//   - 防御单一 DRBG 实现的潜在缺陷（比如某个后端有未知偏差）
//   - 种子分别从同一主种子派生，派生路径不同
//   - 主状态仍由两个后端各自维护，前向保密和抗泄漏由各自实现
type MixedDRBG struct {
	hmac *HMACDRBG
	ctr  *CTRDRBG

	totalBytes int64
}

func NewMixedDRBG(seed []byte) (*MixedDRBG, error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("Mixed-DRBG 种子至少 32 字节，当前 %d", len(seed))
	}

	h := sha256.New()
	h.Write([]byte("mixed-hmac-seed-v1"))
	h.Write(seed)
	hmacSeed := h.Sum(nil)

	h = sha256.New()
	h.Write([]byte("mixed-ctr-seed-v1"))
	h.Write(seed)
	ctrSeed := h.Sum(nil)

	hmacDRBG, err := NewHMACDRBG(hmacSeed)
	secureZeroHard(hmacSeed)
	if err != nil {
		secureZeroHard(ctrSeed)
		return nil, err
	}

	ctrDRBG, err := NewCTRDRBG(ctrSeed)
	secureZeroHard(ctrSeed)
	if err != nil {
		return nil, err
	}

	return &MixedDRBG{hmac: hmacDRBG, ctr: ctrDRBG}, nil
}

// mixedParallelThreshold 小于此大小时串行（goroutine 启动开销 > 并行收益）。
// RGBA_STREAM 每帧约 65KB，远大于阈值，走并行。
// GET_SEED 每次 32B，走串行，节省 goroutine 创建。
const mixedParallelThreshold = 1024

func (m *MixedDRBG) Generate(n int) []byte {
	if n <= 0 {
		return nil
	}

	var hOut, cOut []byte
	if n < mixedParallelThreshold {
		// 小 n 串行
		hOut = m.hmac.Generate(n)
		cOut = m.ctr.Generate(n)
	} else {
		// 大 n 并行：HMAC 和 CTR 是独立 DRBG（无共享锁）
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); hOut = m.hmac.Generate(n) }()
		go func() { defer wg.Done(); cOut = m.ctr.Generate(n) }()
		wg.Wait()
	}

	if len(hOut) != n || len(cOut) != n {
		secureZeroHard(hOut)
		secureZeroHard(cOut)
		return nil
	}
	// 恒定时间 XOR
	for i := 0; i < n; i++ {
		hOut[i] ^= cOut[i]
	}
	secureZeroHard(cOut)
	atomic.AddInt64(&m.totalBytes, int64(n))
	return hOut
}

func (m *MixedDRBG) Mix(entropy []byte) {
	m.hmac.Mix(entropy)
	m.ctr.Mix(entropy)
}

func (m *MixedDRBG) Stats() (int64, int64) {
	hb, hr := m.hmac.Stats()
	cb, cr := m.ctr.Stats()
	return hb + cb, hr + cr
}

func (m *MixedDRBG) Name() string {
	return "mixed (HMAC-SHA256 + AES-256-CTR XOR, split-key + refresh)"
}
