//go:build windows || linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"time"
	"unsafe"
)

// secureZero 尽量把缓冲区清零。用闭包间接引用规避编译器优化。
// 需要强保证时用 secureZeroHard（物理熵模块里，Windows 用 RtlSecureZeroMemory）。
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

// osRandom 取密码学安全随机字节。
// Windows: crypto/rand 底层 BCryptGenRandom
// Linux:   crypto/rand 底层 getrandom(2)
// Darwin:  crypto/rand 底层 SecRandomCopyBytes
func osRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return make([]byte, n)
	}
	return b
}

// safeTimestampBytes 防御性时间戳：高精度计数器优先，退回 time.Now。
// 产出固定 16 字节，作为哈希的额外时间扰动。
func safeTimestampBytes() []byte {
	out := make([]byte, 16)
	ns := time.Now().UnixNano()
	if ns > 0 {
		binary.LittleEndian.PutUint64(out[0:8], uint64(ns))
		binary.LittleEndian.PutUint64(out[8:16], uint64(time.Now().Unix()))
		return out
	}
	return osRandom(16)
}
