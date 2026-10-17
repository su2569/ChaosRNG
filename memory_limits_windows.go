//go:build windows

package main

import "unsafe"

// QueryFreeMemory 通过 MEMORYSTATUSEX 取空闲物理内存和可用 SWAP。
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
