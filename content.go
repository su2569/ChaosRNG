//go:build windows

package main

import (
	"io"
	"net/http"
	"sync"
	"time"
)

// ContentEntropyCollector 抓取公开热榜并做纯度筛选后混池。
type ContentEntropyCollector struct {
	pool      *ChaosEntropyPool
	client    *http.Client
	endpoints []string
}

func NewContentEntropyCollector(p *ChaosEntropyPool) *ContentEntropyCollector {
	return &ContentEntropyCollector{
		pool:   p,
		client: &http.Client{Timeout: 10 * time.Second},
		endpoints: []string{
			"https://hacker-news.firebaseio.com/v0/topstories.json",
			"https://api.bilibili.com/x/web-interface/popular?ps=20&pn=1",
			"https://api.github.com/search/repositories?q=stars:%3E10000&sort=updated&per_page=20",
			"https://www.zhihu.com/api/v3/feed/topstory/hot-lists/total?limit=50",
			"https://api.bilibili.com/x/web-interface/ranking/v2",
		},
	}
}

// FetchAll 并发抓取，成功才混池；纯度不足时压缩或拒绝。
func (c *ContentEntropyCollector) FetchAll() int {
	type out struct{ data []byte }
	var wg sync.WaitGroup
	ch := make(chan out, len(c.endpoints))
	for i, url := range c.endpoints {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			time.Sleep(time.Duration(i*200) * time.Millisecond)
			req, err := http.NewRequest("GET", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (ChaosRNG)")
			req.Header.Set("Accept", "application/json,text/plain,*/*")
			resp, err := c.client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
			if err != nil || len(body) == 0 {
				return
			}
			ch <- out{body}
		}(i, url)
	}
	wg.Wait()
	close(ch)
	n := 0
	for o := range ch {
		c.pool.MixBytesFiltered(o.data)
		secureZero(o.data)
		n++
	}
	return n
}
