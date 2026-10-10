//go:build windows

package main

import (
	"crypto/sha256"
	"io"
	"net/http"
	"sync"
	"time"
)

// 【修复】删掉只写不读的 ring buffer 及相关 mutex。
// 内容熵直接 SHA256 后混池即可；无去重需求时 ring buffer 是纯浪费。
type ContentEntropyCollector struct {
	pool      *ChaosEntropyPool
	client    *http.Client
	endpoints []string
}

func NewContentEntropyCollector(p *ChaosEntropyPool) *ContentEntropyCollector {
	return &ContentEntropyCollector{
		pool:   p,
		client: &http.Client{Timeout: 10 * time.Second},
		// 【修复】替换掉早已失效或需要鉴权的端点；保留稳定可用的公开接口。
		endpoints: []string{
			"https://hacker-news.firebaseio.com/v0/topstories.json",                  // 返回 ID 数组，熵稳定
			"https://api.bilibili.com/x/web-interface/popular?ps=20&pn=1",            // 公开，无需鉴权
			"https://api.github.com/search/repositories?q=stars:%3E10000&sort=updated&per_page=20",
			"https://www.zhihu.com/api/v3/feed/topstory/hot-lists/total?limit=50",     // 可能需 cookie，失败自动跳过
			"https://api.bilibili.com/x/web-interface/ranking/v2",
		},
	}
}

// FetchAll: 并发抓取，成功才混池；失败静默跳过。
// 【修复】不再使用 ring buffer；增加状态码检查，避免把 4xx/5xx 错误页混进池。
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
		h := sha256.Sum256(o.data)
		c.pool.MixBytes(h[:])
		secureZero(o.data)
		n++
	}
	return n
}