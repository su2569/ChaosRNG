//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// QueryFreeMemory 读 /proc/meminfo（Linux）或 sysctl（Darwin 近似）。
// 返回 (空闲物理内存, 可用 SWAP) 字节数。
func QueryFreeMemory() (freePhys, freeSwap int64) {
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "MemAvailable:"):
				freePhys = parseKB(line)
			case strings.HasPrefix(line, "SwapFree:"):
				freeSwap = parseKB(line)
			}
		}
		return
	}
	// Darwin 上没有 /proc，用近似值（sysctl 需要 cgo 或手动解析，这里简化）
	return 0, 0
}

func parseKB(line string) int64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[1], 10, 64)
	return n * 1024
}
