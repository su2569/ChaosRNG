//go:build windows || linux

package main

import (
	"crypto/rand"
	"sync/atomic"
)

// SystemDRBG 用 Go 标准库 crypto/rand（底层是各平台的系统 CSPRNG：
// Windows 是 BCryptGenRandom，Linux 是 getrandom(2)，Darwin 是 SecRandomCopyBytes）。
// 无状态、每次 Generate 都直接取系统熵，天然前向保密。
type SystemDRBG struct {
	totalBytes int64
}

func NewSystemDRBG() *SystemDRBG { return &SystemDRBG{} }

func (s *SystemDRBG) Generate(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	atomic.AddInt64(&s.totalBytes, int64(n))
	return b
}

func (s *SystemDRBG) Mix(_ []byte)          {}
func (s *SystemDRBG) Stats() (int64, int64) { return atomic.LoadInt64(&s.totalBytes), 0 }
func (s *SystemDRBG) Name() string          { return "system (crypto/rand)" }
