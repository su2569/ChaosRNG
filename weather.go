//go:build windows || linux

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 天气熵采集器：wttr.in 抓取各省温度，作为外部真熵混池。对应 aiohttp 版。
type WeatherEntropyCollector struct {
	pool        *ChaosEntropyPool
	client      *http.Client
	cities      map[string]string
	stopCh      chan struct{}
	stopped     bool
	mu          sync.Mutex
	minInterval time.Duration // 节流：两次抓取最小间隔
	lastFetch   time.Time     // 上次实际抓取时间
}

func NewWeatherEntropyCollector(p *ChaosEntropyPool, intervalSec int) *WeatherEntropyCollector {
	if intervalSec <= 0 {
		intervalSec = 300 // 默认 5 分钟
	}
	return &WeatherEntropyCollector{
		pool:        p,
		client:      &http.Client{Timeout: 8 * time.Second},
		cities:      defaultCities(),
		stopCh:      make(chan struct{}),
		minInterval: time.Duration(intervalSec) * time.Second,
	}
}

func defaultCities() map[string]string {
	return map[string]string{
		"北京": "Beijing", "上海": "Shanghai", "广东": "Guangzhou", "江苏": "Nanjing",
		"浙江": "Hangzhou", "四川": "Chengdu", "湖北": "Wuhan", "陕西": "Xi'an",
		"重庆": "Chongqing", "天津": "Tianjin", "河北": "Shijiazhuang", "山西": "Taiyuan",
		"辽宁": "Shenyang", "吉林": "Changchun", "黑龙江": "Harbin", "福建": "Fuzhou",
		"江西": "Nanchang", "山东": "Jinan", "河南": "Zhengzhou", "湖南": "Changsha",
		"广西": "Nanning", "海南": "Haikou", "贵州": "Guiyang", "云南": "Kunming",
		"安徽": "Hefei", "甘肃": "Lanzhou", "青海": "Xining", "内蒙古": "Hohhot",
		"宁夏": "Yinchuan", "新疆": "Urumqi", "西藏": "Lhasa", "香港": "Hong_Kong",
		"澳门": "Macao", "台湾": "Taipei",
	}
}

// FetchOnce: 抽样 sampleCount 个城市并发抓取温度。
func (w *WeatherEntropyCollector) FetchOnce(sampleCount int) int {
	// 节流：距上次抓取不足 minInterval 时跳过
	w.mu.Lock()
	if !w.lastFetch.IsZero() && time.Since(w.lastFetch) < w.minInterval {
		w.mu.Unlock()
		return 0
	}
	w.lastFetch = time.Now()
	w.mu.Unlock()

	type res struct{ prov, temp string }
	keys := make([]string, 0, len(w.cities))
	for k := range w.cities {
		keys = append(keys, k)
	}
	if sampleCount > 0 && sampleCount < len(keys) {
		keys = keys[:sampleCount]
	}
	var wg sync.WaitGroup
	ch := make(chan res, len(keys))
	for _, prov := range keys {
		wg.Add(1)
		go func(prv, city string) {
			defer wg.Done()
			url := fmt.Sprintf("https://wttr.in/%s?format=%%t", city)
			resp, err := w.client.Get(url)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
			if err != nil {
				return
			}
			temp := strings.TrimSpace(string(body))
			if len(temp) > 0 && len(temp) < 10 {
				ch <- res{prv, temp}
			}
		}(prov, w.cities[prov])
	}
	wg.Wait()
	close(ch)
	n := 0
	for r := range ch {
		w.pool.MixEvent(fmt.Sprintf("%s:%s", r.prov, r.temp))
		n++
	}
	return n
}

func (w *WeatherEntropyCollector) Start(interval time.Duration, sample int) {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return
	}
	w.mu.Unlock()
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-w.stopCh:
				return
			case <-t.C:
				w.FetchOnce(sample)
			}
		}
	}()
}

func (w *WeatherEntropyCollector) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		w.stopped = true
		close(w.stopCh)
	}
}
