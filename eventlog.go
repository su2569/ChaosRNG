//go:build windows || linux

package main

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"
)

// EventLogConfig 描述事件采集参数。
type EventLogConfig struct {
	Enable       bool     `json:"enable"`        // 总开关
	IntervalSec  int      `json:"interval_sec"`  // 轮询间隔，默认 15
	MaxEvents    int      `json:"max_events"`    // 每次采集条数，默认 20
	Channels     []string `json:"channels"`      // Windows 日志通道
	UseJournald  bool     `json:"use_journald"`  // Linux 用 journalctl
	FallbackLogs []string `json:"fallback_logs"` // Linux/Darwin 降级日志文件
	DarwinLog    bool     `json:"darwin_log"`    // Darwin 用 log show
}

// EventLogCollector 系统/应用事件熵采集器。
//
// 安全设计：
//   - 事件内容立即 SHA256 哈希后 secureZero，原文不驻留内存
//   - 内容 SHA256 存 recent 环形缓冲（64 项），重复内容不混池
//   - 通过 MixBytesFiltered 走纯度筛选后混入熵池
type EventLogCollector struct {
	pool *ChaosEntropyPool
	cfg  EventLogConfig

	mu       sync.Mutex
	recent   [64][32]byte
	recentN  int
	recentIx int

	totalAttempted int // 尝试混入的事件数（含被拒绝）
	totalAccepted  int // 实际混入池的事件数
	uniqueGain     int
	// 状态字段用 atomic.Int32，避免 collectPlatform 与 Disabled() 数据竞争
	disabled            int32
	consecutiveFailures int32
}

func NewEventLogCollector(p *ChaosEntropyPool, cfg EventLogConfig) *EventLogCollector {
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 15
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > 200 {
		cfg.MaxEvents = 20
	}
	if len(cfg.Channels) == 0 {
		cfg.Channels = []string{"System", "Application"}
	}
	if len(cfg.FallbackLogs) == 0 {
		cfg.FallbackLogs = []string{
			"/var/log/syslog",
			"/var/log/messages",
			"/var/log/kern.log",
			"/var/log/system.log",
		}
	}
	return &EventLogCollector{pool: p, cfg: cfg}
}

// Ingest 把一组事件文本哈希后混池。
// 返回本次混入的新事件数。
func (c *EventLogCollector) Ingest(source string, events []string) int {
	if len(events) == 0 {
		return 0
	}
	unique := 0
	for _, ev := range events {
		if len(ev) < 16 {
			continue // 太短的事件无熵价值
		}

		h := sha256.Sum256([]byte(ev))
		c.mu.Lock()
		if c.seenLocked(h) {
			c.mu.Unlock()
			continue
		}
		// 记录到环形缓冲
		c.recent[c.recentIx] = h
		c.recentIx = (c.recentIx + 1) % len(c.recent)
		if c.recentN < len(c.recent) {
			c.recentN++
		}
		c.mu.Unlock()

		// 混入：源标签 + 事件哈希
		// 不混原文，只混哈希，防泄露
		buf := make([]byte, 0, len(source)+32)
		buf = append(buf, source...)
		buf = append(buf, 0x7C) // '|' 分隔
		buf = append(buf, h[:]...)
		if c.pool.MixBytesFiltered(buf) {
			unique++
		}
		secureZeroHard(buf)
	}
	c.mu.Lock()
	c.totalAttempted += len(events)
	c.totalAccepted += unique
	c.uniqueGain += unique
	c.mu.Unlock()
	return unique
}

// seenLocked 检查 SHA256 是否已在 recent 中
func (c *EventLogCollector) seenLocked(h [32]byte) bool {
	for i := 0; i < c.recentN; i++ {
		idx := (c.recentIx - 1 - i + len(c.recent)) % len(c.recent)
		if c.recent[idx] == h {
			return true
		}
	}
	return false
}

// Stats 返回 (accepted, unique)。
//
// accepted 是实际混入池的事件数（去重 + 通过纯度筛选后），
// unique 是去重后唯一的 SHA256 数量。
// 尝试总数用 TotalAttempted() 单独查。
func (c *EventLogCollector) Stats() (accepted, unique int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalAccepted, c.uniqueGain
}

// TotalAttempted 返回尝试混入的事件总数（含被纯度筛选拒绝的）。
func (c *EventLogCollector) TotalAttempted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalAttempted
}

// Start 启动后台采集 goroutine，返回停止函数。
//
// 停止函数会 close(stopCh) 并等待后台 goroutine 退出。
// 若 goroutine 正在 collectOnce（可能卡在 powershell 子进程），
// 最多等 3 秒后放弃（子进程内部 2s 超时会 kill 自己）。
func (c *EventLogCollector) Start() func() {
	if !c.cfg.Enable {
		return func() {}
	}
	stopCh := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Duration(c.cfg.IntervalSec) * time.Second)
		defer ticker.Stop()

		// 首次立即采集
		c.collectOnce()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				c.collectOnce()
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(stopCh)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				// 采集 goroutine 卡在子进程，超时放弃等待
				// 子进程内部 2s 超时后会被 kill
			}
		})
	}
}

// collectOnce 由平台实现（eventlog_windows.go / eventlog_unix.go）
func (c *EventLogCollector) collectOnce() {
	c.collectPlatform()
}

// Probe 启动时探测事件日志可用性。
// 返回 true 表示可用；false 表示不可用（自动设 disabled = true）。
//
// 探测方式：调用 probePlatform() 试读一次，不混池。
func (c *EventLogCollector) Probe() bool {
	if atomic.LoadInt32(&c.disabled) != 0 {
		return false
	}
	if c.probePlatform() {
		return true
	}
	atomic.StoreInt32(&c.disabled, 1)
	return false
}

// Disabled 返回是否被禁用（启动探测失败或运行中连续失败）。
func (c *EventLogCollector) Disabled() bool {
	return atomic.LoadInt32(&c.disabled) != 0
}

// itoa 避免 strconv 依赖。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
