//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// ConfigFile 是 config.json 的映射。
// 字段用指针来区分"没写"和"写了 false/0/空"。
type ConfigFile struct {
	EntropySources *struct {
		Process *bool `json:"process"`
		System  *bool `json:"system"`
		Memory  *bool `json:"memory"`
		Disk    *bool `json:"disk"`
		Temp    *bool `json:"temp"`
		Input   *bool `json:"input"`
		Weather *bool `json:"weather"`
		Content *bool `json:"content"`
		Packet  *bool `json:"packet"`
		TPM     *bool `json:"tpm"`
		OneBot  *bool `json:"onebot"`
	} `json:"entropy_sources"`

	OneBot *struct {
		Enable       *bool   `json:"enable"`
		HTTPURL      *string `json:"http_url"`
		WSURL        *string `json:"ws_url"`
		Token        *string `json:"token"`
		PollSec      *int    `json:"poll_interval"`
		HistorySize  *int    `json:"history_size"`
		EnableWS     *bool   `json:"enable_ws"`
	} `json:"onebot"`

	TCPServer *struct {
		Host *string `json:"host"`
		Port *int    `json:"port"`
	} `json:"tcp_server"`
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
		if s.Process != nil { cfg.Sources.Process = *s.Process; n++ }
		if s.System  != nil { cfg.Sources.System  = *s.System;  n++ }
		if s.Memory  != nil { cfg.Sources.Memory  = *s.Memory;  n++ }
		if s.Disk    != nil { cfg.Sources.Disk    = *s.Disk;    n++ }
		if s.Temp    != nil { cfg.Sources.Temp    = *s.Temp;    n++ }
		if s.Input   != nil { cfg.Sources.Input   = *s.Input;   n++ }
		if s.Weather != nil { cfg.Sources.Weather = *s.Weather; n++ }
		if s.Content != nil { cfg.Sources.Content = *s.Content; n++ }
		if s.Packet  != nil { cfg.Sources.Packet  = *s.Packet;  n++ }
		if s.TPM     != nil { cfg.Sources.TPM     = *s.TPM;     n++ }
		if s.OneBot  != nil { cfg.Sources.OneBot  = *s.OneBot;  n++ }
	}

	if o := f.OneBot; o != nil {
		if o.Enable != nil { cfg.Sources.OneBot = *o.Enable; n++ }
		cfg.OneBotHTTP     = strOr(o.HTTPURL,     cfg.OneBotHTTP);     n++
		cfg.OneBotWS       = strOr(o.WSURL,       cfg.OneBotWS);       n++
		cfg.OneBotToken    = strOr(o.Token,       cfg.OneBotToken);    n++
		cfg.OneBotPollSec  = intOr(o.PollSec,     cfg.OneBotPollSec);  n++
		cfg.OneBotHistory  = intOr(o.HistorySize, cfg.OneBotHistory);  n++
		cfg.OneBotEnableWS = boolOr(o.EnableWS,   cfg.OneBotEnableWS); n++
	}

	if t := f.TCPServer; t != nil {
		cfg.TCPHost = strOr(t.Host, cfg.TCPHost); n++
		cfg.TCPPort = intOr(t.Port, cfg.TCPPort); n++
	}

	return n, nil
}