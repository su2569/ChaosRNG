//go:build windows

package main

import (
	"crypto/rand"
	"encoding/binary"
	"syscall"
	"time"
	"unsafe"
)

// 共享的 Windows API 动态加载与底层工具。
var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	moduser32   = syscall.NewLazyDLL("user32.dll")

	procGetSystemTimes            = modkernel32.NewProc("GetSystemTimes")
	procGetProcessTimes           = modkernel32.NewProc("GetProcessTimes")
	procQueryPerformanceCounter   = modkernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = modkernel32.NewProc("QueryPerformanceFrequency")
	procGlobalMemoryStatusEx      = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGlobalMemoryStatus        = modkernel32.NewProc("GlobalMemoryStatus")
	procGetTickCount64            = modkernel32.NewProc("GetTickCount64")
	procVirtualQuery              = modkernel32.NewProc("VirtualQuery")
	procRtlGenRandom              = modadvapi32.NewProc("SystemFunction036") // RtlGenRandom
)

// secureZero 尽量把缓冲区清零。Go 有 GC/移动，无法像 C 的 SecureZeroMemory 那样
// 强保证不残留，这里用闭包间接引用规避编译器把清零优化掉。
func secureZero(b []byte) {
	clearFn := func(p *byte, n int) {
		for i := 0; i < n; i++ {
			*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i))) = 0
		}
	}
	if len(b) > 0 {
		clearFn(&b[0], len(b))
	}
}

// osRandom 取密码学安全随机字节：优先 RtlGenRandom(SystemFunction036)，
// 失败回退 crypto/rand（Go 在 Windows 上底层同样是系统 CSPRNG）。
func osRandom(n int) []byte {
	b := make([]byte, n)
	if procRtlGenRandom.Find() == nil {
		r1, _, _ := procRtlGenRandom.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(n))
		if r1 != 0 {
			return b
		}
	}
	_, _ = rand.Read(b)
	return b
}

// safeTimestampBytes 防御性时间戳：优先高精度计数器，再 time.Now，
// 数值不合理时兜底随机。产出固定 16 字节，作为哈希的额外时间扰动。
func safeTimestampBytes() []byte {
	out := make([]byte, 16)
	if procQueryPerformanceFrequency.Find() == nil && procQueryPerformanceCounter.Find() == nil {
		var freq, cnt int64
		r1, _, _ := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&freq)))
		if r1 != 0 && freq > 0 {
			r2, _, _ := procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&cnt)))
			if r2 != 0 && cnt > 0 {
				binary.LittleEndian.PutUint64(out[0:8], uint64(cnt))
				binary.LittleEndian.PutUint64(out[8:16], uint64(freq))
				return out
			}
		}
	}
	// 【修复】原条件 `ns > 1<<60` 语义不明，实际近似恒真。改用明确的时间合理性检查：
	//   UnixNano > 0 表示 RTC 已被初始化；否则退回 osRandom。
	ns := time.Now().UnixNano()
	if ns > 0 {
		binary.LittleEndian.PutUint64(out[0:8], uint64(ns))
		binary.LittleEndian.PutUint64(out[8:16], uint64(time.Now().Unix()))
		return out
	}
	return osRandom(16)
}
