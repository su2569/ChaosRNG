//go:build windows || linux

package main

import (
	"runtime"
	"sync"
	"unsafe"
)

var physicalMu sync.Mutex

// secureZeroFallback 通用清零（Windows 上由 RtlSecureZeroMemory 替代）。
// 用 noinline + KeepAlive 尽量阻止编译器优化掉清零。
//
//go:noinline
func secureZeroFallback(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// basicEntropyHealth 检查物理熵至少有 16 种不同字节。
// 纯软件熵源在启动时最容易退化，这个检查能提前拦截。
func basicEntropyHealth(data []byte) bool {
	if len(data) < 32 {
		return false
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	uniq := 0
	for _, c := range freq {
		if c > 0 {
			uniq++
		}
	}
	return uniq >= 16
}

// makeAddrJitter 通过连续分配得到堆地址的低位抖动。
// 跨平台通用；Go GC 不保证地址固定，正是我们想要的抖动来源。
func makeAddrJitter() []byte {
	var b [8]byte
	var keep []interface{}
	for i := 0; i < 8; i++ {
		p := make([]byte, 64)
		addr := uintptr(unsafe.Pointer(&p[0]))
		b[i] = byte(addr)
		keep = append(keep, p)
	}
	runtime.KeepAlive(keep)
	return b[:]
}
