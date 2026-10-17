//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const eventlogMaxConsecutiveFailures = 3

// collectPlatform 三级 fallback 读 Windows 事件。
func (c *EventLogCollector) collectPlatform() {
	if atomic.LoadInt32(&c.disabled) != 0 {
		return
	}

	// 并行采集多个通道（PowerShell 冷启动 ~500ms + 查询 ~1.5s/通道）
	type channelResult struct {
		ch     string
		events []string
		method string
	}
	resultCh := make(chan channelResult, len(c.cfg.Channels))
	for _, chName := range c.cfg.Channels {
		go func(name string) {
			events, method := readWinEventsAuto(name, c.cfg.MaxEvents)
			resultCh <- channelResult{ch: name, events: events, method: method}
		}(chName)
	}
	allFailed := true
	for i := 0; i < len(c.cfg.Channels); i++ {
		r := <-resultCh
		if r.method == "all-failed" {
			LogDebug("eventlog", "Win %s: 所有读取方法均失败", r.ch)
			continue
		}
		allFailed = false
		if len(r.events) == 0 {
			LogDebug("eventlog", "Win %s: 采集成功但无事件（%s）", r.ch, r.method)
			continue
		}
		n := c.Ingest("win:"+r.ch, r.events)
		LogDebug("eventlog", "Win %s: 采集 %d 条（%s），新事件 %d 条", r.ch, len(r.events), r.method, n)
	}

	if allFailed {
		n := atomic.AddInt32(&c.consecutiveFailures, 1)
		if n >= eventlogMaxConsecutiveFailures {
			atomic.StoreInt32(&c.disabled, 1)
			LogWarn("eventlog",
				"连续 %d 次所有方法均失败，已自动禁用事件日志熵源", n)
		}
	} else {
		atomic.StoreInt32(&c.consecutiveFailures, 0)
	}
}

// probePlatform 启动时并行探测多个通道，任一成功即返回。
// 缩短启动延迟（原来是顺序探测，两通道 × 2s PowerShell 冷启动 = 4s+）。
func (c *EventLogCollector) probePlatform() bool {
	if len(c.cfg.Channels) == 0 {
		return false
	}
	type probeRes struct {
		ch     string
		method string
	}
	ch := make(chan probeRes, len(c.cfg.Channels))
	// 并行探测多个通道
	for _, chName := range c.cfg.Channels {
		go func(name string) {
			_, method := readWinEventsAuto(name, 1)
			ch <- probeRes{name, method}
		}(chName)
	}
	totalTimeout := time.After(3 * time.Second)
	for i := 0; i < len(c.cfg.Channels); i++ {
		select {
		case r := <-ch:
			if r.method != "all-failed" {
				LogDebug("eventlog", "启动探测：%s 可用（方法=%s）", r.ch, r.method)
				return true
			}
		case <-totalTimeout:
			return false
		}
	}
	return false
}

// readWinEventsAuto 三级 fallback。
func readWinEventsAuto(channel string, count int) ([]string, string) {
	// 1. 绝对路径 wevtutil
	if abs := wevtutilAbsPath(); abs != "" {
		if ev := readViaWevtutil(abs, channel, count); ev != nil {
			return ev, "wevtutil-abs"
		}
	}

	// 2. PATH wevtutil
	if _, err := exec.LookPath("wevtutil"); err == nil {
		if ev := readViaWevtutil("wevtutil", channel, count); ev != nil {
			return ev, "wevtutil-path"
		}
	}

	// 3. PowerShell Get-WinEvent
	if ev := readViaPowerShell(channel, count); ev != nil {
		return ev, "powershell"
	}

	return nil, "all-failed"
}

func wevtutilAbsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	p := filepath.Join(root, "System32", "wevtutil.exe")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func readViaWevtutil(exe, channel string, count int) []string {
	cmd := exec.Command(exe, "qe", channel,
		"/c:"+itoa(count), "/rd:true", "/f:text")

	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		ch <- res{out, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			LogDebug("eventlog", "wevtutil %s 失败: %v, 输出: %q",
				channel, r.err, truncateStr(string(r.out), 200))
			return nil
		}
		return splitWinEvents(string(r.out))
	case <-time.After(3 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		LogDebug("eventlog", "wevtutil %s 超时", channel)
		return nil
	}
}

// readViaPowerShell 用 PowerShell Get-WinEvent 读事件（PS 2.0 兼容）。
// 不用 ConvertTo-Json（PS 3.0+ 才有），改用 -f 格式化每行一条事件。
func readViaPowerShell(channel string, count int) []string {
	// Message 里的换行和 | 替换，避免破坏"一行一条"格式
	psScript := fmt.Sprintf(
		"Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction SilentlyContinue | "+
			"ForEach-Object { "+
			"$m = $_.Message; "+
			"if ($m) { $m = $m -replace \"[`r`n]+\", ' ' -replace '\\|', '/' } "+
			"'{0}|{1}|{2}|{3}|{4}' -f $_.Id, $_.TimeCreated, $_.ProviderName, $_.LevelDisplayName, $m "+
			"}",
		channel, count)

	cmd := exec.Command("powershell.exe",
		"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", psScript)

	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		ch <- res{out, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			LogDebug("eventlog", "powershell %s 失败: %v, 输出: %q",
				channel, r.err, truncateStr(string(r.out), 200))
			return nil
		}
		text := string(r.out)
		// 去 UTF-8 BOM 和可能的 UTF-16 BOM
		text = strings.TrimPrefix(text, "\ufeff")
		text = strings.TrimPrefix(text, "\xff\xfe")
		text = strings.TrimSpace(text)
		if text == "" {
			return []string{}
		}
		lines := strings.Split(text, "\n")
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// 事件行应包含至少 3 个 |
			if len(line) > 16 && strings.Count(line, "|") >= 3 {
				out = append(out, line)
			}
		}
		return out
	case <-time.After(8 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		LogDebug("eventlog", "powershell %s 超时", channel)
		return nil
	}
}

// truncateStr 截断字符串便于日志输出。
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// splitWinEvents 把 wevtutil /f:text 输出按 "Event[N]:" 分割。
func splitWinEvents(text string) []string {
	if text == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Event[") && strings.HasSuffix(trimmed, "]:") {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		} else if trimmed != "" {
			cur.WriteString(line)
			cur.WriteByte('\n')
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
