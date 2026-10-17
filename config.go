//go:build windows || linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ConfigFile 是 config.json 的映射。
// 字段用指针来区分"没写"和"写了 false/0/空"。
type ConfigFile struct {
	EntropySources *struct {
		Process  *bool `json:"process"`
		System   *bool `json:"system"`
		Memory   *bool `json:"memory"`
		Disk     *bool `json:"disk"`
		Temp     *bool `json:"temp"`
		Input    *bool `json:"input"`
		Weather  *bool `json:"weather"`
		Content  *bool `json:"content"`
		Packet   *bool `json:"packet"`
		TPM      *bool `json:"tpm"`
		OneBot   *bool `json:"onebot"`
		EventLog *bool `json:"eventlog"`
	} `json:"entropy_sources"`

	OneBot *struct {
		Enable      *bool   `json:"enable"`
		HTTPURL     *string `json:"http_url"`
		WSURL       *string `json:"ws_url"`
		Token       *string `json:"token"`
		PollSec     *int    `json:"poll_interval"`
		HistorySize *int    `json:"history_size"`
		EnableWS    *bool   `json:"enable_ws"`
	} `json:"onebot"`

	TCPServer *struct {
		Host *string `json:"host"`
		Port *int    `json:"port"`
	} `json:"tcp_server"`

	Server *struct {
		StreamMaxConcurrent *int     `json:"stream_max_concurrent"`
		StreamMaxDuration   *int     `json:"stream_max_duration"`
		PushRatePerSec      *float64 `json:"push_rate_per_sec"`
		PushRateBurst       *int     `json:"push_rate_burst"`
	} `json:"server"`

	EventLog *struct {
		Enable       *bool    `json:"enable"`
		IntervalSec  *int     `json:"interval_sec"`
		MaxEvents    *int     `json:"max_events"`
		Channels     []string `json:"channels"`
		UseJournald  *bool    `json:"use_journald"`
		FallbackLogs []string `json:"fallback_logs"`
		DarwinLog    *bool    `json:"darwin_log"`
	} `json:"eventlog"`

	Weather *struct {
		IntervalSec *int `json:"interval_sec"`
	} `json:"weather"`

	Content *struct {
		IntervalSec *int `json:"interval_sec"`
	} `json:"content"`
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
func strOr(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}
func intOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// loadConfigJSON: 读 config.json 并覆盖到 cfg。返回成功覆盖的字段数。
func loadConfigJSON(path string, cfg *Config) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var f ConfigFile
	if err := json.Unmarshal(data, &f); err != nil {
		return 0, fmt.Errorf("json parse: %w", err)
	}

	n := 0

	if s := f.EntropySources; s != nil {
		if s.Process != nil {
			cfg.Sources.Process = *s.Process
			n++
		}
		if s.System != nil {
			cfg.Sources.System = *s.System
			n++
		}
		if s.Memory != nil {
			cfg.Sources.Memory = *s.Memory
			n++
		}
		if s.Disk != nil {
			cfg.Sources.Disk = *s.Disk
			n++
		}
		if s.Temp != nil {
			cfg.Sources.Temp = *s.Temp
			n++
		}
		if s.Input != nil {
			cfg.Sources.Input = *s.Input
			n++
		}
		if s.Weather != nil {
			cfg.Sources.Weather = *s.Weather
			n++
		}
		if s.Content != nil {
			cfg.Sources.Content = *s.Content
			n++
		}
		if s.Packet != nil {
			cfg.Sources.Packet = *s.Packet
			n++
		}
		if s.TPM != nil {
			cfg.Sources.TPM = *s.TPM
			n++
		}
		if s.OneBot != nil {
			cfg.Sources.OneBot = *s.OneBot
			n++
		}
		if s.EventLog != nil {
			cfg.Sources.EventLog = *s.EventLog
			n++
		}
	}

	if o := f.OneBot; o != nil {
		if o.Enable != nil {
			cfg.Sources.OneBot = *o.Enable
			n++
		}
		cfg.OneBotHTTP = strOr(o.HTTPURL, cfg.OneBotHTTP)
		n++
		cfg.OneBotWS = strOr(o.WSURL, cfg.OneBotWS)
		n++
		cfg.OneBotToken = strOr(o.Token, cfg.OneBotToken)
		n++
		cfg.OneBotPollSec = intOr(o.PollSec, cfg.OneBotPollSec)
		n++
		cfg.OneBotHistory = intOr(o.HistorySize, cfg.OneBotHistory)
		n++
		cfg.OneBotEnableWS = boolOr(o.EnableWS, cfg.OneBotEnableWS)
		n++
	}

	if t := f.TCPServer; t != nil {
		cfg.TCPHost = strOr(t.Host, cfg.TCPHost)
		n++
		cfg.TCPPort = intOr(t.Port, cfg.TCPPort)
		n++
	}

	if srv := f.Server; srv != nil {
		if srv.StreamMaxConcurrent != nil {
			cfg.StreamMaxConcurrent = *srv.StreamMaxConcurrent
			n++
		}
		if srv.StreamMaxDuration != nil {
			cfg.StreamMaxDuration = *srv.StreamMaxDuration
			n++
		}
		if srv.PushRatePerSec != nil {
			cfg.PushRatePerSec = *srv.PushRatePerSec
			n++
		}
		if srv.PushRateBurst != nil {
			cfg.PushRateBurst = *srv.PushRateBurst
			n++
		}
	}

	if el := f.EventLog; el != nil {
		if el.Enable != nil {
			cfg.EventLog.Enable = *el.Enable
			n++
		}
		if el.IntervalSec != nil {
			cfg.EventLog.IntervalSec = *el.IntervalSec
			n++
		}
		if el.MaxEvents != nil {
			cfg.EventLog.MaxEvents = *el.MaxEvents
			n++
		}
		if len(el.Channels) > 0 {
			cfg.EventLog.Channels = el.Channels
			n++
		}
		if el.UseJournald != nil {
			cfg.EventLog.UseJournald = *el.UseJournald
			n++
		}
		if len(el.FallbackLogs) > 0 {
			cfg.EventLog.FallbackLogs = el.FallbackLogs
			n++
		}
		if el.DarwinLog != nil {
			cfg.EventLog.DarwinLog = *el.DarwinLog
			n++
		}
	}

	if w := f.Weather; w != nil && w.IntervalSec != nil {
		cfg.WeatherIntervalSec = *w.IntervalSec
		n++
	}
	if c := f.Content; c != nil && c.IntervalSec != nil {
		cfg.ContentIntervalSec = *c.IntervalSec
		n++
	}

	return n, nil
}

// resolveConfigPath 决定最终使用的配置文件路径。
//
// 行为：
//  1. 用户显式 -config <路径>（flagSet=true）→ 直接信任，不做 fallback
//  2. 默认 "config.json"（flagSet=false）：
//     a. 当前工作目录下有 → 用 CWD 的
//     b. exe 所在目录下有 → 用 exe 目录的（方便从其他目录启动）
//     c. 都没有 → 返回 CWD 的（后续 loadConfigJSON 会报错，日志明确）
//
// 第二个返回值 source 用于日志区分：flag / cwd / exe / cwd-missing
func resolveConfigPath(name string, flagSet bool) (string, string) {
	if flagSet {
		return name, "flag"
	}

	// a. 当前目录
	if _, err := os.Stat(name); err == nil {
		return name, "cwd"
	}

	// b. 程序所在目录
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidate := filepath.Join(exeDir, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, "exe"
		}
	}

	// c. 都没有，返回 CWD 路径
	return name, "cwd-missing"
}
