//go:build linux

package main

import "os"

// Unix 终端（Linux tty / macOS Terminal / iTerm）默认支持 ANSI 转义序列。
// 除非输出被重定向到文件（此时 isatty 为 false），一律视为支持。
var vtSupported bool

func enableVT() bool {
	f, err := os.OpenFile("/dev/stdout", os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	vtSupported = true
	return true
}
