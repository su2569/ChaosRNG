//go:build windows || linux

package main

import (
	"math"
	"math/bits"
)

// 纯度筛选参数（0~100）
//
// 说明：purityRejectBelow / purityHighEnough 是 32 字节样本的"标准阈值"，
// 保留用于固定 32 字节种子的 pushHexSeed 场景。
// 大小不定的样本（如熵源采集、MIX 命令）应使用 purityThresholds 动态阈值。
const (
	purityRejectBelow = 30.0 // 32 字节标准：拒绝线
	purityHighEnough  = 90.0 // 32 字节标准：直混线
	purityMinBytes    = 32   // 短于此长度跳过纯度筛选
)

// purityThresholds 按样本大小返回 (rejectBelow, highEnough)。
//
// 理论依据：
//
//	32 字节（256 bit）样本 Shannon 熵理论上限 log2(32)≈5，
//	实际真随机常在 4.5~5.0，Monobit 有 ~2% 概率偏离 >2σ，
//	导致大量真随机种子落在 78~85 分，90 阈值下都会被压缩。
//	小样本统计功效不足，应放宽阈值；大样本统计可靠，可用标准阈值。
//
// 阈值矩阵：
//
//	n < 32      → 不筛选（0, 100），统计不可靠
//	32 ≤ n < 64 → (20, 75)，2~4σ 随机波动区
//	64 ≤ n < 256 → (25, 82)，逐步收紧
//	256 ≤ n < 1024 → (28, 87)
//	n ≥ 1024    → (30, 90)，标准阈值
func purityThresholds(n int) (float64, float64) {
	switch {
	case n < purityMinBytes:
		return 0, 100
	case n < 64:
		return 20, 75
	case n < 256:
		return 25, 82
	case n < 1024:
		return 28, 87
	default:
		return purityRejectBelow, purityHighEnough
	}
}

// ComputePurity 综合 Shannon 熵、Monobit 均衡度、Runs 均衡度，返回 0~100 纯度分。
func ComputePurity(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	var H float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(n)
		H -= p * math.Log2(p)
	}
	maxH := math.Log2(math.Min(float64(n), 256.0))
	shannon := 0.0
	if maxH > 0 {
		shannon = H / maxH * 100.0
	}

	ones := 0
	for _, b := range data {
		ones += bits.OnesCount8(b)
	}
	total := n * 8
	dev := math.Abs(float64(ones) - float64(total)/2.0)
	mono := 100.0 - dev/float64(total)*200.0
	if mono < 0 {
		mono = 0
	}

	runs := 1
	var prev byte
	first := true
	for _, b := range data {
		for k := 7; k >= 0; k-- {
			bit := (b >> uint(k)) & 1
			if !first && bit != prev {
				runs++
			}
			prev = bit
			first = false
		}
	}
	expected := float64(total+1) / 2.0
	runsDev := math.Abs(float64(runs)-expected) / expected * 100.0
	runsScore := 100.0 - runsDev
	if runsScore < 0 {
		runsScore = 0
	}

	return 0.40*shannon + 0.30*mono + 0.30*runsScore
}

// CondenseEntropy 有损压缩：去连续重复字节 + VonNeumann 纠偏。
func CondenseEntropy(data []byte) []byte {
	if len(data) < 8 {
		return nil
	}
	dedup := make([]byte, 0, len(data))
	var last byte
	has := false
	for _, b := range data {
		if !has || b != last {
			dedup = append(dedup, b)
			last = b
			has = true
		}
	}
	if len(dedup) < 8 {
		secureZero(dedup)
		return nil
	}
	vn := VonNeumann(dedup)
	secureZero(dedup)
	if len(vn) < 4 {
		secureZero(vn)
		return nil
	}
	return vn
}
