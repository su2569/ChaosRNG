//go:build linux

package main

// TPMEntropyCollector 在 Unix 上默认降级为 Available()=false。
// Linux 若需 TPM 支持，可后续扩展读 /dev/tpm0（需要 root 或 tss 组）。
type TPMEntropyCollector struct {
	pool  *ChaosEntropyPool
	avail bool
}

func NewTPMEntropyCollector(p *ChaosEntropyPool) *TPMEntropyCollector {
	return &TPMEntropyCollector{pool: p, avail: false}
}

func (c *TPMEntropyCollector) Available() bool { return c.avail }

func (c *TPMEntropyCollector) Collect() {
	// no-op
}

func (c *TPMEntropyCollector) Close() {
	// no-op
}
