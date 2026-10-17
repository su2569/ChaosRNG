//go:build windows

package main

import (
	"math"
	"math/bits"
)

// 纯度筛选参数（0~100）
const (
	purityRejectBelow = 30.0
	purityHighEnough  = 70.0
	purityMinBytes    = 32
)

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
