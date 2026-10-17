//go:build windows || linux

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

type logLevel int

const (
	lvlDebug logLevel = iota
	lvlInfo
	lvlWarn
	lvlError
)

var lvlNames = [4]string{"DEBUG", "INFO ", "WARN ", "ERROR"}

type logger struct {
	mu      sync.Mutex
	level   logLevel
	out     io.Writer
	rotator *rotateWriter
	color   bool
}

var lg = &logger{level: lvlInfo, out: os.Stdout, color: true}

// InitLogger 设置日志级别、输出目标与彩色开关。
//
//	levelStr: debug/info/warn/error（空视为 info）
//	filePath: 非空时同时写入该文件（追加模式）
//	noColor:  true 时禁用 ANSI 彩色前缀
func InitLogger(levelStr, filePath string, noColor bool, maxSize int64, backupCount int) error {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "", "info", "i":
		lg.level = lvlInfo
	case "debug", "d":
		lg.level = lvlDebug
	case "warn", "warning", "w":
		lg.level = lvlWarn
	case "error", "e":
		lg.level = lvlError
	default:
		return fmt.Errorf("无效日志级别 %q（可选 debug/info/warn/error）", levelStr)
	}

	if filePath != "" {
		rw, err := NewRotateWriter(filePath, maxSize, backupCount)
		if err != nil {
			return fmt.Errorf("打开日志文件 %q 失败: %w", filePath, err)
		}
		lg.rotator = rw
		lg.out = io.MultiWriter(os.Stdout, rw)
	}

	// 彩色判定：用户显式 -no-color、NO_COLOR 环境变量、控制台 VT 支持
	lg.color = !noColor && os.Getenv("NO_COLOR") == "" && vtSupported
	return nil
}

// CloseLogger 关闭日志文件（若有）。
func CloseLogger() {
	if lg.rotator != nil {
		lg.rotator.Close()
		lg.rotator = nil
	}
}

func (l *logger) logf(lvl logLevel, tag, format string, args ...interface{}) {
	if lvl < l.level {
		return
	}
	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("2006-01-02 15:04:05.000")

	var line string
	if l.color && tag != "" {
		color := colorForLevel(lvl)
		line = fmt.Sprintf("%s %s[%s]\x1b[0m [%s] %s\n", ts, color, lvlNames[lvl], tag, msg)
	} else {
		line = fmt.Sprintf("%s [%s] [%s] %s\n", ts, lvlNames[lvl], tag, msg)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.out, line)
}

func colorForLevel(lvl logLevel) string {
	switch lvl {
	case lvlDebug:
		return "\x1b[90m"
	case lvlInfo:
		return "\x1b[36m"
	case lvlWarn:
		return "\x1b[33m"
	case lvlError:
		return "\x1b[31m"
	}
	return ""
}

func LogDebug(tag, format string, args ...interface{}) { lg.logf(lvlDebug, tag, format, args...) }
func LogInfo(tag, format string, args ...interface{})  { lg.logf(lvlInfo, tag, format, args...) }
func LogWarn(tag, format string, args ...interface{})  { lg.logf(lvlWarn, tag, format, args...) }
func LogError(tag, format string, args ...interface{}) { lg.logf(lvlError, tag, format, args...) }
