//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var procRtlSecureZeroMemory = modkernel32.NewProc("RtlSecureZeroMemory")

// secureZeroHard 用 RtlSecureZeroMemory 强制清零（Windows 保证不被优化）。
func secureZeroHard(b []byte) {
	if len(b) == 0 {
		return
	}
	if procRtlSecureZeroMemory.Find() == nil {
		procRtlSecureZeroMemory.Call(
			uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
		return
	}
	secureZeroFallback(b)
}

// CollectPhysicalEntropy 从软件可访问的物理过程采集 n 字节熵。
//
// 熵来源：QPC 抖动、进程 CPU 差、内存地址抖动、系统空闲时间、时间戳。
// 不调用任何系统 CSPRNG。
func CollectPhysicalEntropy(n int) []byte {
	physicalMu.Lock()
	defer physicalMu.Unlock()

	h := sha256.New()
	h.Write([]byte("chaosrng-physical-win-v1"))

	for i := 0; i < 16; i++ {
		ts := waitTickChange()
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], ts)
		h.Write(b[:])
	}

	cpuBytes := measureCPUDiff()
	h.Write(cpuBytes)
	secureZeroHard(cpuBytes)

	addrJitter := makeAddrJitter()
	h.Write(addrJitter)
	secureZeroHard(addrJitter)

	idleBytes := measureIdleDiff()
	h.Write(idleBytes)

	var tb [8]byte
	binary.LittleEndian.PutUint64(tb[:], uint64(time.Now().UnixNano()))
	h.Write(tb[:])

	result := h.Sum(nil)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = result[i%len(result)]
	}
	secureZeroHard(result)
	return out
}

func waitTickChange() uint64 {
	prev := readTick()
	deadline := time.Now().Add(time.Millisecond)
	for time.Now().Before(deadline) {
		cur := readTick()
		if cur != prev {
			return cur
		}
		runtime.Gosched()
	}
	return prev
}

func readTick() uint64 {
	var cnt int64
	if procQueryPerformanceCounter.Find() == nil {
		procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&cnt)))
	}
	return uint64(cnt)
}

func measureCPUDiff() []byte {
	var creation, exit, kern, user syscall.Filetime
	var b [16]byte
	hProc, _, _ := procGetCurrentProcess.Call()
	r, _, _ := procGetProcessTimes.Call(hProc,
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&user)))
	if r != 0 {
		kt := uint64(kern.HighDateTime)<<32 | uint64(kern.LowDateTime)
		ut := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
		binary.LittleEndian.PutUint64(b[0:8], kt)
		binary.LittleEndian.PutUint64(b[8:16], ut)
	}
	return b[:]
}

func measureIdleDiff() []byte {
	var idle, kern, user syscall.Filetime
	var b [8]byte
	if procGetSystemTimes.Find() == nil {
		r, _, _ := procGetSystemTimes.Call(
			uintptr(unsafe.Pointer(&idle)),
			uintptr(unsafe.Pointer(&kern)),
			uintptr(unsafe.Pointer(&user)))
		if r != 0 {
			binary.LittleEndian.PutUint64(b[:],
				uint64(idle.LowDateTime)^uint64(idle.HighDateTime)<<32)
		}
	}
	return b[:]
}
