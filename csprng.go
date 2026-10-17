//go:build windows || linux

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// DRBG 是软件 CSPRNG 后端接口。
//
// 实现需保证：
//  1. Generate(n) 输出密码学安全的 n 字节
//  2. 每次 Generate 内部 ratchet（前向保密），拿到当前 state 无法反推历史
//  3. Mix(entropy) 混入额外熵
//  4. 线程安全
type DRBG interface {
	Generate(n int) []byte
	Mix(entropy []byte)
	Stats() (totalBytes, ratchets int64)
	Name() string
}

// NewDRBG 按 kind 选择后端：
//
//	system: 系统 CSPRNG（crypto/rand，跨平台）
//	hmac:   HMAC-SHA256 DRBG（NIST SP 800-90A）
//	ctr:    AES-256-CTR DRBG（NIST SP 800-90A）
//	none:   PhysicalDRBG（纯物理熵，无 DRBG）
func NewDRBG(kind, seedFile string) (DRBG, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "", "system":
		return NewSystemDRBG(), nil
	case "hmac", "hmac-sha256":
		seed, err := loadSeed(seedFile)
		if err != nil {
			return nil, fmt.Errorf("HMAC-DRBG 种子失败: %w", err)
		}
		d, err := NewHMACDRBG(seed)
		secureZeroHard(seed)
		return d, err
	case "ctr", "aes-ctr":
		seed, err := loadSeed(seedFile)
		if err != nil {
			return nil, fmt.Errorf("CTR-DRBG 种子失败: %w", err)
		}
		d, err := NewCTRDRBG(seed)
		secureZeroHard(seed)
		return d, err
	case "mixed", "hybrid":
		seed, err := loadSeed(seedFile)
		if err != nil {
			return nil, fmt.Errorf("Mixed-DRBG 种子失败: %w", err)
		}
		d, err := NewMixedDRBG(seed)
		secureZeroHard(seed)
		return d, err
	case "none", "physical":
		return NewPhysicalDRBG(), nil
	default:
		return nil, fmt.Errorf("未知 DRBG 类型 %q（可选 system/hmac/ctr/mixed/none）", kind)
	}
}

// loadSeed 按优先级加载种子：
//  1. seedFile 存在且 >= 32 字节 → 用户种子（hex 优先，其次二进制）
//  2. seedFile 为空 → 物理熵采集 + 健康测试
func loadSeed(seedFile string) ([]byte, error) {
	if seedFile != "" {
		data, err := os.ReadFile(seedFile)
		if err != nil {
			return nil, fmt.Errorf("读取种子文件失败: %w", err)
		}
		trimmed := strings.TrimSpace(string(data))
		if len(trimmed) >= 64 {
			if h, herr := hex.DecodeString(trimmed); herr == nil && len(h) >= 32 {
				return h, nil
			}
		}
		if len(data) >= 32 {
			return data, nil
		}
		return nil, fmt.Errorf("种子文件至少 32 字节（hex 或二进制），当前 %d", len(data))
	}
	seed := CollectPhysicalEntropy(64)
	if !basicEntropyHealth(seed) {
		secureZeroHard(seed)
		return nil, fmt.Errorf("物理熵采集健康测试未通过（建议 -seed-file 提供用户种子）")
	}
	return seed, nil
}
