//go:build linux

package main

import "os"

// PermissionManager 在 Unix 上不做 UAC 提权。
// IsAdmin 通过 euid == 0 判断，Elevate 返回 false（用户需要手动 sudo）。
type PermissionManager struct {
	elevatedArg string
}

func NewPermissionManager() *PermissionManager {
	return &PermissionManager{elevatedArg: "--elevated"}
}

// IsAdmin 检查 euid 是否为 0（root）。
func (pm *PermissionManager) IsAdmin() bool {
	return os.Geteuid() == 0
}

// Elevate Unix 上不做提权，返回 false。用户需自己 `sudo ./chaos_rng`。
func (pm *PermissionManager) Elevate() bool {
	return false
}

// HasElevatedFlag 检查 --elevated（Unix 上无意义，恒返回 false）。
func (pm *PermissionManager) HasElevatedFlag() bool {
	return false
}
