//go:build windows

package main

import (
	"encoding/binary"
	"syscall"
	"time"
	"unsafe"
)

// 进程快照采集器：遍历进程 CPU 时间做前后差分，抖动作为物理熵混池。
// 对应 psutil 遍历进程（此处用 Toolhelp32 快照，纯 kernel32，无第三方）。
type ProcessSnapshotCollector struct {
	pool *ChaosEntropyPool
	prev map[uint32]uint64
	have bool
}

func NewProcessSnapshotCollector(p *ChaosEntropyPool) *ProcessSnapshotCollector {
	return &ProcessSnapshotCollector{pool: p, prev: make(map[uint32]uint64)}
}

var (
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modkernel32.NewProc("Process32NextW")
)

type processEntry32 struct {
	dwSize              uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	th32CntUsage        uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

const th32csSnapProcess = 0x00000002

// procKernelUserTimes 取指定进程的 (kernel+user) 累计 100ns 时间。
var (
	procOpenProcess = modkernel32.NewProc("OpenProcess")
	// CloseHandle 已在 entropy_sensors.go 里声明为 procCloseHandle，直接复用
)

func procKernelUserTimes(pid uint32) (uint64, bool) {
	// 【修复】使用包级 procOpenProcess / procCloseHandle
	h, _, _ := procOpenProcess.Call(0x1000, 0, uintptr(pid))
	if h == 0 {
		return 0, false
	}
	defer procCloseHandle.Call(h)
	var creation, exit, kern, user syscall.Filetime
	r, _, _ := procGetProcessTimes.Call(h,
		uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return 0, false
	}
	kt := uint64(kern.HighDateTime)<<32 | uint64(kern.LowDateTime)
	ut := uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime)
	return kt + ut, true
}

func (c *ProcessSnapshotCollector) snapshot() map[uint32]uint64 {
	cur := make(map[uint32]uint64)
	h, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if h == uintptr(0xffffffffffffffff) {
		return cur
	}
	defer procCloseHandle.Call(h)
	var pe processEntry32
	pe.dwSize = uint32(unsafe.Sizeof(pe))
	r, _, _ := procProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&pe)))
	for r != 0 {
		pid := pe.th32ProcessID
		if t, ok := procKernelUserTimes(pid); ok {
			cur[pid] = t
		} else {
			cur[pid] = 0
		}
		r, _, _ = procProcess32NextW.Call(h, uintptr(unsafe.Pointer(&pe)))
	}
	return cur
}

// Collect: 前后两次快照差分，进程消亡/新生/CPU 显著抖动混池。
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
				// 新生进程
				binary.LittleEndian.PutUint32(bin[4:8], 0xdead)
				c.pool.MixBytesFiltered(bin[:])
				n++
			} else if pt > 0 && t > pt+10000 {
				// 【修复】pt == 0 表示上一轮 OpenProcess 失败，此时 t 是绝对值，
				// 不应参与抖动差分，否则会灌入大量伪噪声。
				binary.LittleEndian.PutUint32(bin[4:8], uint32(t-pt))
				c.pool.MixBytesFiltered(bin[:])
				n++
			}
		}
		for pid := range c.prev {
			if _, ok := cur[pid]; !ok {
				// 进程消亡
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
