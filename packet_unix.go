//go:build linux

package main

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// PacketCollector 在 Linux 上用 AF_PACKET 原始套接字。
// 需要 CAP_NET_RAW 或 root；否则 Collect 返回 0。
type PacketCollector struct {
	pool      *ChaosEntropyPool
	usedNpcap bool // 保持接口兼容（Unix 上恒 false）
	iface     string
	aesKey    []byte

	mu sync.Mutex
	// 用 int32 + atomic 避免 Collect/Probe（加锁）与 Disabled（无锁）数据竞争
	disabled            int32
	consecutiveFailures int32
}

func NewPacketCollector(p *ChaosEntropyPool) *PacketCollector {
	return &PacketCollector{
		pool:   p,
		aesKey: deriveAESKey(p),
	}
}

func (c *PacketCollector) UsingNpcap() bool { return false }

// Collect 用 AF_PACKET 原始套接字采集最多 count 个帧。
func (c *PacketCollector) Collect(count int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.LoadInt32(&c.disabled) != 0 {
		return 0
	}

	fd, err := syscall.Socket(17, syscall.SOCK_RAW, 0x0003) // ETH_P_ALL
	if err != nil {
		atomic.AddInt32(&c.consecutiveFailures, 1)
		if atomic.LoadInt32(&c.consecutiveFailures) >= 3 {
			atomic.StoreInt32(&c.disabled, 1)
			LogWarn("packet", "连续 3 次 AF_PACKET socket 失败（需要 CAP_NET_RAW 或 root），已自动禁用")
		}
		return 0
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 1})

	buf := make([]byte, 65535)
	deadline := time.Now().Add(2 * time.Second)
	n := 0
	for n < count && time.Now().Before(deadline) {
		nb, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || nb <= 0 {
			continue
		}
		c.mixEncrypted(buf[:nb])
		n++
	}
	if n > 0 {
		atomic.StoreInt32(&c.consecutiveFailures, 0)
	}
	return n
}

// Probe 启动时探测抓包可用性。
// 试创建 AF_PACKET socket，成功即可用。
func (c *PacketCollector) Probe() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if atomic.LoadInt32(&c.disabled) != 0 {
		return false
	}
	fd, err := syscall.Socket(17, syscall.SOCK_RAW, 0x0003)
	if err != nil {
		atomic.StoreInt32(&c.disabled, 1)
		LogDebug("packet", "启动探测：AF_PACKET socket 失败: %v（需要 CAP_NET_RAW 或 root）", err)
		return false
	}
	syscall.Close(fd)
	LogDebug("packet", "启动探测：AF_PACKET 可用")
	return true
}

// mixEncrypted: 随机 IV + AES-256-CTR -> SHA256(IV||CT) -> 混池。
func (c *PacketCollector) mixEncrypted(payload []byte) {
	if len(payload) == 0 {
		return
	}
	var toMix []byte = payload
	var cond []byte
	if len(payload) >= purityMinBytes {
		purity := ComputePurity(payload)
		if purity < purityRejectBelow {
			return
		}
		if purity < purityHighEnough {
			cond = CondenseEntropy(payload)
			if len(cond) == 0 {
				return
			}
			toMix = cond
		}
	}
	if cond != nil {
		defer secureZero(cond)
	}
	iv := osRandom(ctrIVLen)
	ct := aes256CTR(c.aesKey, iv, toMix)
	if ct == nil {
		return
	}
	h := sha256.New()
	h.Write(iv)
	h.Write(ct)
	sum := h.Sum(nil)
	c.pool.MixBytes(sum)
	secureZero(ct)
}

// Disabled 返回是否因连续失败被自动禁用或启动探测失败。
// 用 atomic 无锁读，不阻塞 Collect。
func (c *PacketCollector) Disabled() bool {
	return atomic.LoadInt32(&c.disabled) != 0
}
