//go:build windows || linux

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// interactiveShell: 简易控制台，与 Python 原版命令对齐。
func interactiveShell(
	pool *ChaosEntropyPool,
	srv *TCPServer,
	obClient *OneBotClient,
	weather *WeatherEntropyCollector,
	content *ContentEntropyCollector,
	caps map[string]bool,
	stop func(),
) {
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("🔥 Chaos RNG 控制台")
	fmt.Println("命令: seed, lucky, status, caps, collect, weather, content, help, quit")
	fmt.Println("==================================================")
	fmt.Println()

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 4096), 1<<20)
	for {
		fmt.Print("chaos> ")
		if !sc.Scan() {
			stop()
			return
		}
		cmd := strings.ToLower(strings.TrimSpace(sc.Text()))
		switch cmd {
		case "":
			continue
		case "quit", "q", "exit":
			stop()
			return

		case "seed":
			seed := GenerateSeed(pool)
			fmt.Println("🎲", hex.EncodeToString(seed))
			secureZero(seed)

		case "lucky":
			seed := GenerateSeed(pool)
			var n uint64
			for i := 0; i < 8 && i < len(seed); i++ {
				n = (n << 8) | uint64(seed[i])
			}
			fmt.Printf("🍀 %d / 100\n", n%100+1)
			secureZero(seed)

		case "status":
			b, _ := json.MarshalIndent(srv.status(), "", "  ")
			fmt.Println(string(b))

		case "caps":
			for k, v := range caps {
				mark := "❌"
				if v {
					mark = "✅"
				}
				fmt.Printf("  %s %s\n", mark, k)
			}

		case "help", "h", "?":
			fmt.Println("本地命令：")
			fmt.Println("  seed     - 生成一个 32B 种子（hex）")
			fmt.Println("  lucky    - 幸运数字 1~100")
			fmt.Println("  status   - 输出服务器 JSON 状态")
			fmt.Println("  caps     - 显示能力开关")
			fmt.Println("  collect  - OneBot 混入计数")
			fmt.Println("  weather  - 立即抓一次天气")
			fmt.Println("  content  - 立即抓一次热榜")
			fmt.Println("  help     - 本帮助")
			fmt.Println("  quit     - 退出")
			fmt.Println()
			fmt.Println("TCP 命令（用 nc/脚本发到 18888）：")
			fmt.Println("  GET_SEED / GET_HEX / GET_SEEDS <n>")
			fmt.Println("  RGBA [size] / RGBA_STREAM [size] [fps] / STOP")
			fmt.Println("  PUSH_SEED <hex> / MIX <hex> / PING / CAPS / STATUS <key> / HELP")
			fmt.Println("  连接后发送 HELP 可看完整清单")

		case "collect":
			if obClient != nil {
				h, w := obClient.Stats()
				fmt.Printf("💬 OneBot HTTP 混入=%d WS 事件混入=%d\n", h, w)
			} else {
				fmt.Println("❌ OneBot 未启用")
			}

		case "weather":
			if weather != nil {
				n := weather.FetchOnce(12)
				fmt.Printf("🌤️ 抓取 %d 个城市\n", n)
			} else {
				fmt.Println("❌ 天气未启用")
			}

		case "content":
			if content != nil {
				n := content.FetchAll()
				fmt.Printf("📰 抓取 %d 个平台\n", n)
			} else {
				fmt.Println("❌ 内容未启用")
			}

		default:
			fmt.Println("未知命令，输入 help 查看列表")
		}
	}
}
