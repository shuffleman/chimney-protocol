// speedtest: 高并发上传/下载测速工具，通过 HTTP 代理运行
//
// 用法（内置本地测速服务器）:
//   speedtest -proxy http://127.0.0.1:2080 -dl 8 -ul 4 -duration 30s
//
// 使用外网节点（仅下载）:
//   speedtest -proxy http://127.0.0.1:2080 -dl 4 -ul 0 -duration 30s \
//     -dlurl https://speed.cloudflare.com/__down?bytes=104857600
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

var (
	proxyAddr  = flag.String("proxy", "http://127.0.0.1:2080", "HTTP 代理地址")
	dlWorkers  = flag.Int("dl", 4, "并发下载 worker 数")
	ulWorkers  = flag.Int("ul", 4, "并发上传 worker 数")
	duration   = flag.Duration("duration", 30*time.Second, "测试持续时间")
	dlURL      = flag.String("dlurl", "", "下载 URL（空则使用内置服务器）")
	ulURL      = flag.String("ulurl", "", "上传 URL（空则使用内置服务器）")
	serverPort = flag.Int("serverport", 19876, "内置测速服务器端口")
	verbose    = flag.Bool("v", false, "显示每个 worker 的错误详情")
)

// 512KB 随机数据块（复用于所有上传）
var uploadBuf [512 * 1024]byte

type stats struct {
	dlBytes  atomic.Int64
	ulBytes  atomic.Int64
	dlErrors atomic.Int64
	ulErrors atomic.Int64
	dlConns  atomic.Int64
	ulConns  atomic.Int64
}

// startLocalServer 启动内置 HTTP 测速服务器
func startLocalServer(port int) (string, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		buf := make([]byte, 64*1024)
		rand.Read(buf)
		// 持续输出直到客户端断开
		for {
			if _, err := w.Write(buf); err != nil {
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	})

	mux.HandleFunc("/ul", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	go http.Serve(ln, mux)
	return addr, nil
}

func newClient(proxyURL string) (*http.Client, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(u),
			MaxIdleConnsPerHost: 64,
		},
		// 不设置 Timeout，改用 context 控制
	}, nil
}

func downloadWorker(id int, client *http.Client, targetURL string, s *stats, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 128*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.dlConns.Add(1)
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.dlErrors.Add(1)
			if *verbose {
				log.Printf("[DL#%d] 失败: %v", id, err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var n int64
		for {
			nr, err := resp.Body.Read(buf)
			if nr > 0 {
				n += int64(nr)
				s.dlBytes.Add(int64(nr))
			}
			if err != nil {
				break
			}
		}
		resp.Body.Close()
		if *verbose && n > 0 {
			elapsed := time.Since(start)
			log.Printf("[DL#%d] %.1f MB in %.1fs = %.1f Mbps", id,
				float64(n)/1e6, elapsed.Seconds(), float64(n)*8/elapsed.Seconds()/1e6)
		}
	}
}

func uploadWorker(id int, client *http.Client, targetURL string, s *stats, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	// 固定大小 body，避免 chunked transfer encoding 与 HTTP CONNECT 代理不兼容
	chunkSize := len(uploadBuf)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.ulConns.Add(1)
		start := time.Now()

		body := bytes.NewReader(uploadBuf[:chunkSize])
		req, _ := http.NewRequestWithContext(ctx, "POST", targetURL, body)
		req.ContentLength = int64(chunkSize)
		req.Header.Set("Content-Type", "application/octet-stream")

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.ulErrors.Add(1)
			if *verbose {
				log.Printf("[UL#%d] 失败: %v", id, err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		elapsed := time.Since(start)
		s.ulBytes.Add(int64(chunkSize))
		if *verbose {
			mbps := float64(chunkSize) * 8 / elapsed.Seconds() / 1e6
			log.Printf("[UL#%d] %.1f MB in %.1fs = %.1f Mbps", id, float64(chunkSize)/1e6, elapsed.Seconds(), mbps)
		}
	}
}

func main() {
	flag.Parse()
	rand.Read(uploadBuf[:])

	// 启动内置服务器
	actualDLURL := *dlURL
	actualULURL := *ulURL
	if actualDLURL == "" || actualULURL == "" {
		addr, err := startLocalServer(*serverPort)
		if err != nil {
			log.Fatalf("启动本地测速服务器失败: %v", err)
		}
		log.Printf("内置测速服务器: http://%s", addr)
		if actualDLURL == "" {
			actualDLURL = fmt.Sprintf("http://%s/dl", addr)
		}
		if actualULURL == "" {
			actualULURL = fmt.Sprintf("http://%s/ul", addr)
		}
	}

	log.Printf("=== Chimney 并发测速 ===")
	log.Printf("代理: %s", *proxyAddr)
	log.Printf("下载: %s  并发: %d", actualDLURL, *dlWorkers)
	log.Printf("上传: %s  并发: %d", actualULURL, *ulWorkers)
	log.Printf("时长: %s", *duration)

	dlClient, _ := newClient(*proxyAddr)
	ulClient, _ := newClient(*proxyAddr)

	s := &stats{}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < *dlWorkers; i++ {
		wg.Add(1)
		go downloadWorker(i+1, dlClient, actualDLURL, s, ctx, &wg)
	}
	for i := 0; i < *ulWorkers; i++ {
		wg.Add(1)
		go uploadWorker(i+1, ulClient, actualULURL, s, ctx, &wg)
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	startTime := time.Now()
	var prevDL, prevUL int64
	prevTime := startTime

	fmt.Printf("\n%-6s  %-12s  %-12s  %-10s  %-10s  %-8s  %-8s\n",
		"时间", "下载速度", "上传速度", "下载总量", "上传总量", "DL错误", "UL错误")
	fmt.Println("──────────────────────────────────────────────────────────────────────")

	for {
		select {
		case <-ctx.Done():
			goto done
		case t := <-ticker.C:
			nowDL := s.dlBytes.Load()
			nowUL := s.ulBytes.Load()
			elapsed := t.Sub(prevTime).Seconds()
			dlSpeed := float64(nowDL-prevDL) * 8 / elapsed / 1e6
			ulSpeed := float64(nowUL-prevUL) * 8 / elapsed / 1e6
			prevDL, prevUL = nowDL, nowUL
			prevTime = t
			fmt.Printf("%-6.0fs  %-12s  %-12s  %-10s  %-10s  %-8d  %-8d\n",
				t.Sub(startTime).Seconds(),
				fmt.Sprintf("%.1f Mbps", dlSpeed),
				fmt.Sprintf("%.1f Mbps", ulSpeed),
				humanBytes(nowDL), humanBytes(nowUL),
				s.dlErrors.Load(), s.ulErrors.Load(),
			)
		}
	}

done:
	wg.Wait()

	totalTime := time.Since(startTime).Seconds()
	totalDL := s.dlBytes.Load()
	totalUL := s.ulBytes.Load()
	totalDLErr := s.dlErrors.Load()
	totalULErr := s.ulErrors.Load()

	fmt.Println("\n══════════════════ 测试结果 ══════════════════")
	fmt.Printf("测试时长:      %.1f 秒\n", totalTime)
	fmt.Printf("下载总量:      %s  (平均 %.1f Mbps)\n", humanBytes(totalDL), float64(totalDL)*8/totalTime/1e6)
	fmt.Printf("上传总量:      %s  (平均 %.1f Mbps)\n", humanBytes(totalUL), float64(totalUL)*8/totalTime/1e6)
	fmt.Printf("下载连接:  总 %-6d  错误 %-6d  成功率 %.1f%%\n",
		s.dlConns.Load(), totalDLErr, 100*float64(s.dlConns.Load()-totalDLErr)/max1(s.dlConns.Load()))
	fmt.Printf("上传连接:  总 %-6d  错误 %-6d  成功率 %.1f%%\n",
		s.ulConns.Load(), totalULErr, 100*float64(s.ulConns.Load()-totalULErr)/max1(s.ulConns.Load()))

	if totalDLErr+totalULErr == 0 {
		fmt.Println("\n✓ 稳定性: 全部连接成功，无错误")
	} else {
		fmt.Printf("\n✗ 稳定性: %d 个错误 (DL:%d UL:%d)\n", totalDLErr+totalULErr, totalDLErr, totalULErr)
	}
}

func humanBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
	default:
		return fmt.Sprintf("%.2f GB", float64(b)/1024/1024/1024)
	}
}

func max1(v int64) float64 {
	if v <= 0 {
		return 1
	}
	return float64(v)
}
