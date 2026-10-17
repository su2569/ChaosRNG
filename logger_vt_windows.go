//go:build windows

package main

import "unsafe"

// enableVT 启用 Windows 10+ 控制台的 ANSI 转义序列支持。
// STD_OUTPUT_HANDLE = -11 = 0xfffffff5，STD_ERROR_HANDLE = -12 = 0xfffffff4
var (
	procGetStdHandle   = modkernel32.NewProc("GetStdHandle")
	procGetConsoleMode = modkernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = modkernel32.NewProc("SetConsoleMode")
)

var vtSupported bool

func enableVT() bool {
	const enableVirtTerm = 0x0004
	h, _, _ := procGetStdHandle.Call(0xfffffff5)
	if h == 0 || h == ^uintptr(0) {
		return false
	}
	var mode uint32
	if r, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode))); r == 0 {
		return false
	}
	if mode&enableVirtTerm != 0 {
		vtSupported = true
		return true
	}
	procSetConsoleMode.Call(h, uintptr(mode|enableVirtTerm))
	var mode2 uint32
	if r2, _, _ := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode2))); r2 != 0 && mode2&enableVirtTerm != 0 {
		vtSupported = true
		return true
	}
	return false
}
