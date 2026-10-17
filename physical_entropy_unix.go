//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"runtime"
	"syscall"
	"time"
)

// secureZeroHard 在 Unix 上走通用 fallback（无 RtlSecureZeroMemory）。
func secureZeroHard(b []byte) {
	secureZeroFallback(b)
}

// CollectPhysicalEntropy 从软件可访问的物理过程采集 n 字节熵。
//
// 熵来源：clock 抖动、进程 CPU（Getrusage）、内存地址抖动、时间戳。
// 不调用任何系统 CSPRNG。
func CollectPhysicalEntropy(n int) []byte {
	physicalMu.Lock()
	defer physicalMu.Unlock()

	h := sha256.New()
	h.Write([]byte("chaosrng-physical-unix-v1"))

	// 1. 时间抖动（clock_gettime 精度 ns 级）
	var prev int64 = time.Now().UnixNano()
	for i := 0; i < 32; i++ {
		for {
			now := time.Now().UnixNano()
			if now != prev {
				prev = now
				break
			}
			runtime.Gosched()
		}
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], uint64(prev))
		h.Write(b[:])
	}

	// 2. 进程 CPU 时间（user + sys）
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err == nil {
		var b [16]byte
		binary.LittleEndian.PutUint64(b[0:8],
			uint64(ru.Utime.Sec)*1e9+uint64(ru.Utime.Usec)*1e3)
		binary.LittleEndian.PutUint64(b[8:16],
			uint64(ru.Stime.Sec)*1e9+uint64(ru.Stime.Usec)*1e3)
		h.Write(b[:])
	}

	// 3. 内存地址抖动
	addrJitter := makeAddrJitter()
	h.Write(addrJitter)
	secureZeroHard(addrJitter)

	// 4. 时间戳
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
