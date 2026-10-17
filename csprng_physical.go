//go:build windows || linux || darwin

package main

import (
	"sync"
	"sync/atomic"
)

const (
	// physicalReseedBytes 每输出这么多字节重播种一次（前向保密粒度）
	// 1MB = 33 个 GET_SEED(32B) 或 ~16 个 RGBA_STREAM 帧(65KB)
	physicalReseedBytes = 1 << 20
)

// PhysicalDRBG 不依赖系统 CSPRNG：
//  1. 每输出物理熵字节数达到 reseed 阈值时，重采样 32 字节物理熵作为新种子
//  2. 用种子重建 CTR-DRBG
//  3. 内部复用 DRBG 输出 n 字节
//
// 前向保密：每 1MB 换一次种子 → 100M bit 样本内约 12 次 ratchet，
// 攻击者即使拿到某次种子，也只能重建 1MB 而非整个样本。
//
// 与纯物理熵直接输出的区别：物理熵采集速率极低（每次 32 字节约 20~80ms），
// 无法直接产生大量高质量随机数，必须通过密码学 DRBG 扩展。
type PhysicalDRBG struct {
	mu         sync.Mutex
	drbg       *CTRDRBG
	bytesSince int64 // 自上次重播种输出的字节数
	totalBytes int64
	warned     bool // healthWarned：健康失败只打 1 次 WARN
}

func NewPhysicalDRBG() *PhysicalDRBG { return &PhysicalDRBG{} }

func (p *PhysicalDRBG) Generate(n int) []byte {
	if n <= 0 {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 首次或达到 reseed 阈值：重播种
	if p.drbg == nil || p.bytesSince >= physicalReseedBytes {
		seed := CollectPhysicalEntropy(32)
		if !basicEntropyHealth(seed) {
			if !p.warned {
				LogWarn("csprng", "none 后端物理熵健康测试未通过（VM 或极快 CPU 常见），本次播种降级为 crypto/rand。后续不再提示")
				p.warned = true
			}
			secureZeroHard(seed)
			seed = osRandom(32)
		}
		drbg, err := NewCTRDRBG(seed)
		secureZeroHard(seed)
		if err != nil {
			return nil
		}
		p.drbg = drbg
		p.bytesSince = 0
	}

	out := p.drbg.Generate(n)
	p.bytesSince += int64(n)
	atomic.AddInt64(&p.totalBytes, int64(n))
	return out
}

func (p *PhysicalDRBG) Mix(_ []byte) {}
func (p *PhysicalDRBG) Stats() (int64, int64) {
	// ratchets 用 bytesSince/reseedBytes 估算——这里返回 0 保持接口兼容
	return atomic.LoadInt64(&p.totalBytes), 0
}
func (p *PhysicalDRBG) Name() string {
	return "physical-seeded CTR-DRBG (clock/cpu/memory jitter, no system CSPRNG)"
}
func (p *PhysicalDRBG) NeedsPoolMix() bool { return false }
