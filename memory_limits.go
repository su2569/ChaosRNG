//go:build windows

package main

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"
	"unsafe"
)

const (
	memMinXms     = int64(20) << 20
	warnThreshold = int64(16) << 30
)

// ParseMemSize 解析内存大小字符串，返回字节数。
// 支持：20M / 1024M / 1G / 512K / 1048576B / 1024(纯数字=MB)
func ParseMemSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1) << 20
	switch s[len(s)-1] {
	case 'b', 'B':
		mult = 1
		s = s[:len(s)-1]
	case 'k', 'K':
		mult = 1 << 10
		s = s[:len(s)-1]
	case 'm', 'M':
		mult = 1 << 20
		s = s[:len(s)-1]
	case 'g', 'G':
		mult = 1 << 30
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size")
	}
	return n * mult, nil
}

// QueryFreeMemory 返回空闲物理内存和可用 SWAP（近似）。
func QueryFreeMemory() (freePhys, freeSwap int64) {
	type memEx struct {
		dwLength                uint32
		dwMemoryLoad            uint32
		ullTotalPhys            uint64
		ullAvailPhys            uint64
		ullTotalPageFile        uint64
		ullAvailPageFile        uint64
		ullTotalVirtual         uint64
		ullAvailVirtual         uint64
		ullAvailExtendedVirtual uint64
	}
	var m memEx
	m.dwLength = uint32(unsafe.Sizeof(m))
	if procGlobalMemoryStatusEx.Find() != nil {
		return 0, 0
	}
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return 0, 0
	}
	freePhys = int64(m.ullAvailPhys)
	freeSwap = int64(m.ullAvailPageFile) - freePhys
	if freeSwap < 0 {
		freeSwap = 0
	}
	return
}

// ApplyMemoryLimits 校验 -Xms/-Xmx 并设置 Go 软上限。
func ApplyMemoryLimits(xms, xmx int64) (int64, int64, error) {
	freePhys, freeSwap := QueryFreeMemory()
	avail := freePhys + freeSwap

	if xms < memMinXms {
		xms = memMinXms
	}
	if xmx <= 0 {
		xmx = warnThreshold
		if avail > 0 && avail < xmx {
			xmx = avail
		}
	}
	if avail > 0 && xmx > avail {
		return 0, 0, fmt.Errorf("-Xmx=%d 超过系统空闲内存+SWAP总和(%d 字节)", xmx, avail)
	}
	if xmx < memMinXms {
		return 0, 0, fmt.Errorf("-Xmx=%d 低于最低要求 %d 字节（系统空闲内存不足）", xmx, memMinXms)
	}
	if xmx > warnThreshold && avail > 0 {
		fmt.Printf("[mem] 警告：-Xmx=%d 超过 16GB（%d 字节），但小于空闲总和(%d 字节)，继续\n",
			xmx, warnThreshold, avail)
	}
	if xms > xmx {
		xms = xmx
	}
	debug.SetMemoryLimit(xmx)
	fmt.Printf("[mem] -Xms=%d 字节 -Xmx=%d 字节（软上限）\n", xms, xmx)
	return xms, xmx, nil
}
