//go:build linux

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// collectPlatform Linux 优先 journalctl，降级读日志文件；
// Darwin 优先 log show，降级读日志文件。
func (c *EventLogCollector) collectPlatform() {
	collected := false

	// 1. systemd journal（Linux）
	if runtime.GOOS == "linux" && c.cfg.UseJournald {
		events := readJournald(c.cfg.MaxEvents)
		if len(events) > 0 {
			n := c.Ingest("journald", events)
			LogDebug("eventlog", "journald: 采集 %d 条，新事件 %d 条", len(events), n)
			collected = true
		}
	}

	// 3. 文件日志降级（所有 Unix）
	for _, path := range c.cfg.FallbackLogs {
		events := readLogTail(path, c.cfg.MaxEvents)
		if len(events) > 0 {
			n := c.Ingest("file:"+path, events)
			LogDebug("eventlog", "文件 %s: 采集 %d 条，新事件 %d 条", path, len(events), n)
			collected = true
			break // 一个文件够用，不遍历全部
		}
	}

	if !collected {
		LogDebug("eventlog", "所有事件源不可用（journalctl/log show/日志文件）")
	}
}

// readJournald 用 journalctl 读最近事件。
// journalctl -n N --no-pager -o short-iso -p info
func readJournald(count int) []string {
	cmd := exec.Command(
		"journalctl",
		"-n", itoa(count),
		"--no-pager",
		"-o", "short-iso",
		"-p", "info",
	)
	type res struct {
		out []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		out, err := cmd.Output()
		ch <- res{out, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil // 命令失败
		}
		// 命令成功：即使无内容也返回空 slice（不 nil）
		lines := splitLines(string(r.out))
		if lines == nil {
			return []string{}
		}
		return lines
	case <-time.After(3 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return nil
	}
}

// readLogTail 读日志文件最后 N 行（最多读最后 64KB，避免大文件开销）。
func readLogTail(path string, count int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil
	}
	size := st.Size()
	const maxRead = 64 * 1024
	offset := int64(0)
	if size > maxRead {
		offset = size - maxRead
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return nil
	}

	data := make([]byte, size-offset)
	n, err := f.Read(data)
	if err != nil && n == 0 {
		return nil
	}
	data = data[:n]

	lines := strings.Split(string(data), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	// 过滤空行和太短的行
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if len(l) > 32 {
			out = append(out, l)
		}
	}
	// 成功读到内容但全被过滤：返回空 slice 而非 nil
	if out == nil {
		return []string{}
	}
	return out
}

func splitLines(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if len(strings.TrimSpace(l)) > 16 {
			out = append(out, l)
		}
	}
	return out
}

// probePlatform Unix 上试读一次 journalctl / 日志文件，判断可用性。
func (c *EventLogCollector) probePlatform() bool {
	tried := false

	if c.cfg.UseJournald {
		tried = true
		if events := readJournald(1); events != nil {
			LogDebug("eventlog", "启动探测：journald 可用")
			return true
		}
	}
	for _, path := range c.cfg.FallbackLogs {
		tried = true
		if events := readLogTail(path, 1); events != nil {
			LogDebug("eventlog", "启动探测：文件 %s 可用", path)
			return true
		}
	}
	if !tried {
		LogDebug("eventlog", "启动探测：未配置任何事件源")
	}
	return false
}
