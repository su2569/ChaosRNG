//go:build linux

package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ================= 系统运行抖动熵（Linux 版） =================

// SystemEntropyCollector 从 /proc/stat、/proc/uptime、/proc/meminfo 采集。
type SystemEntropyCollector struct {
	pool     *ChaosEntropyPool
	lastTick uint64
}

func NewSystemEntropyCollector(p *ChaosEntropyPool) *SystemEntropyCollector {
	return &SystemEntropyCollector{pool: p}
}

func (c *SystemEntropyCollector) Collect() {
	var gc runtime.MemStats
	runtime.ReadMemStats(&gc)

	var buf [48]byte
	// 1. /proc/uptime 的秒级精度抖动
	if f, err := os.Open("/proc/uptime"); err == nil {
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			parts := strings.Fields(sc.Text())
			if len(parts) >= 1 {
				if v, err := strconv.ParseFloat(parts[0], 64); err == nil {
					tick := uint64(v * 1e6)
					for i := 0; i < 4; i++ {
						buf[i] = byte(tick >> uint(8*i))
					}
				}
			}
		}
		f.Close()
	}
	// 2. /proc/stat 的 ctxt（上下文切换计数）
	if f, err := os.Open("/proc/stat"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "ctxt ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if v, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						for i := 0; i < 4; i++ {
							buf[4+i] = byte(v >> uint(8*i))
						}
					}
				}
				break
			}
		}
		f.Close()
	}
	// 3. GC 状态
	buf[8] = byte(gc.NumGC)
	buf[9] = byte(gc.NumGC >> 8)
	buf[10] = byte(runtime.NumGoroutine())
	buf[11] = byte(gc.PauseTotalNs)
	// 4. 时间戳
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		buf[12+i] = byte(ns >> uint(8*i))
	}
	// 5. /proc/meminfo MemFree
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "MemFree:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if v, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						for i := 0; i < 4; i++ {
							buf[20+i] = byte(v >> uint(8*i))
						}
					}
				}
				break
			}
		}
		f.Close()
	}
	c.pool.MixBytesFiltered(buf[:])
	c.lastTick = uint64(ns)
}

// ================= 内存熵 =================

type MemoryEntropyCollector struct{ pool *ChaosEntropyPool }

func NewMemoryEntropyCollector(p *ChaosEntropyPool) *MemoryEntropyCollector {
	return &MemoryEntropyCollector{pool: p}
}

func (c *MemoryEntropyCollector) Collect() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var b [32]byte
	local := make([]byte, 64)
	addr := uintptr(unsafe.Pointer(&local[0]))
	for i := 0; i < 8; i++ {
		b[i] = byte(addr >> uint(8*i))
	}
	for i := 0; i < 8; i++ {
		b[8+i] = byte(ms.NextGC >> uint(8*i))
	}
	for i := 0; i < 8; i++ {
		b[16+i] = byte(ms.TotalAlloc >> uint(8*i))
	}
	for i := 0; i < 4; i++ {
		b[24+i] = byte(ms.HeapAlloc >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
	secureZero(local)
}

// ================= 磁盘统计熵 =================

type DiskEntropyCollector struct{ pool *ChaosEntropyPool }

func NewDiskEntropyCollector(p *ChaosEntropyPool) *DiskEntropyCollector {
	return &DiskEntropyCollector{pool: p}
}

func (c *DiskEntropyCollector) Collect() {
	var st syscall.Statfs_t
	var b [24]byte
	if err := syscall.Statfs("/", &st); err == nil {
		for i := 0; i < 8; i++ {
			b[0+i] = byte(st.Bavail >> uint(8*i))
			b[8+i] = byte(st.Blocks >> uint(8*i))
		}
	}
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[16+i] = byte(ns >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}

// ================= 温度熵 =================

type TemperatureCollector struct {
	pool     *ChaosEntropyPool
	lastTent int32
}

func NewTemperatureCollector(p *ChaosEntropyPool) *TemperatureCollector {
	return &TemperatureCollector{pool: p}
}

func (c *TemperatureCollector) LastTenthsC() int32 { return c.lastTent }

func (c *TemperatureCollector) Collect() {
	// 优先 /sys/class/thermal/thermal_zone0/temp（单位通常为 0.001°C）
	if data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		s := strings.TrimSpace(string(data))
		if v, err := strconv.ParseInt(s, 10, 32); err == nil {
			tenths := int32(v / 100)
			if tenths > 0 && tenths < 2000 {
				c.lastTent = tenths
				var b [8]byte
				for i := 0; i < 4; i++ {
					b[i] = byte(tenths >> uint(8*i))
				}
				ns := time.Now().UnixNano()
				for i := 0; i < 4; i++ {
					b[4+i] = byte(ns >> uint(8*i))
				}
				c.pool.MixBytesFiltered(b[:])
				return
			}
		}
	}
	// 降级：时间戳 + 高精度计数器
	var b [16]byte
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(ns >> uint(8*i))
	}
	// Linux 用第二次 time.Now() 替代 QPC（精度略低但跨平台）
	cnt := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[8+i] = byte(cnt >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}

// ================= 输入抖动熵 =================

type InputEntropyCollector struct{ pool *ChaosEntropyPool }

func NewInputEntropyCollector(p *ChaosEntropyPool) *InputEntropyCollector {
	return &InputEntropyCollector{pool: p}
}

func (c *InputEntropyCollector) Collect() {
	// Linux 上读 /dev/input 需要 root，简化为读 /proc/interrupts 的键鼠中断计数。
	var b [24]byte
	ns := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[i] = byte(ns >> uint(8*i))
	}
	if data, err := os.ReadFile("/proc/interrupts"); err == nil {
		// 只取前 12 字节的累计中断数，避免过大开销
		h := uint64(0)
		for i := 0; i < len(data) && i < 512; i++ {
			h = h*31 + uint64(data[i])
		}
		for i := 0; i < 8; i++ {
			b[8+i] = byte(h >> uint(8*i))
		}
	}
	cnt := time.Now().UnixNano()
	for i := 0; i < 8; i++ {
		b[16+i] = byte(cnt >> uint(8*i))
	}
	c.pool.MixBytesFiltered(b[:])
}
