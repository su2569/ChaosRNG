//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessSnapshotCollector 通过 /proc/*/stat 采集进程 CPU 时间差分。
type ProcessSnapshotCollector struct {
	pool *ChaosEntropyPool
	prev map[uint32]uint64
	have bool
}

func NewProcessSnapshotCollector(p *ChaosEntropyPool) *ProcessSnapshotCollector {
	return &ProcessSnapshotCollector{pool: p, prev: make(map[uint32]uint64)}
}

// snapshot 遍历 /proc/*/stat，取 utime + stime 之和（单位: jiffies）。
func (c *ProcessSnapshotCollector) snapshot() map[uint32]uint64 {
	cur := make(map[uint32]uint64)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return cur
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		path := filepath.Join("/proc", e.Name(), "stat")
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			fields := strings.Fields(sc.Text())
			// /proc/<pid>/stat 格式：pid (comm) state ppid ... 至少 17 个字段
			// utime 是第 14 个字段（从 1 开始），stime 是第 15 个
			if len(fields) >= 15 {
				if ut, err := strconv.ParseUint(fields[13], 10, 64); err == nil {
					if st, err := strconv.ParseUint(fields[14], 10, 64); err == nil {
						cur[uint32(pid)] = ut + st
					}
				}
			}
		}
		f.Close()
	}
	return cur
}

func (c *ProcessSnapshotCollector) Collect() {
	cur := c.snapshot()
	if c.have {
		var acc [16]byte
		n := 0
		for pid, t := range cur {
			pt, existed := c.prev[pid]
			var bin [8]byte
			binary.LittleEndian.PutUint32(bin[0:4], pid)
			if !existed {
				binary.LittleEndian.PutUint32(bin[4:8], 0xdead)
				c.pool.MixBytesFiltered(bin[:])
				n++
			} else if pt > 0 && t > pt {
				binary.LittleEndian.PutUint32(bin[4:8], uint32(t-pt))
				c.pool.MixBytesFiltered(bin[:])
				n++
			}
		}
		for pid := range c.prev {
			if _, ok := cur[pid]; !ok {
				var bin [8]byte
				binary.LittleEndian.PutUint32(bin[0:4], pid)
				binary.LittleEndian.PutUint32(bin[4:8], 0xbeef)
				c.pool.MixBytesFiltered(bin[:])
				n++
			}
		}
		ns := time.Now().UnixNano()
		for i := 0; i < 8; i++ {
			acc[i] = byte(ns >> uint(8*i))
		}
		binary.LittleEndian.PutUint32(acc[8:12], uint32(n))
		c.pool.MixBytesFiltered(acc[:])
	}
	c.prev = cur
	c.have = true
}
