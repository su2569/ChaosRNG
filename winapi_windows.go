//go:build windows

package main

import (
	"syscall"
)

// 共享的 Windows API 动态加载。
// 通用函数（secureZero/osRandom/safeTimestampBytes）在 winapi_common.go。

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
