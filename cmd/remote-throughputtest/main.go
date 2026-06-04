// cmd/remote-throughputtest — 连接到外部 Chimney 中继进行吞吐量测试。
//
// 与内置中继+后端的 throughputtest 不同，此工具期望中继
// 和后端已在远程服务器上运行。客户端连接到
// 远程中继，所有流量完全避免 Windows 回环。
//
// 用法：
//
//	remote-throughputtest -relay 103.135.147.226:8443 -dl 16 -ul 16 -duration 30s -pool 4
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	chimney "github.com/shuffleman/chimney-protocol"
	"github.com/shuffleman/chimney-protocol/internal/record"
)

var (
	relayAddr        = flag.String("relay", "", "Remote relay address (host:port)")
	dlWorkers        = flag.Int("dl", 8, "Download workers")
	ulWorkers        = flag.Int("ul", 8, "Upload workers")
	duration         = flag.Duration("duration", 30*time.Second, "Test duration")
	poolSize         = flag.Int("pool", 4, "Chimney connection pool size")
	bufSize          = flag.Int("buf", 128*1024, "Read/write buffer size (bytes)")
	backend          = flag.String("backend", "127.0.0.1:19444", "Backend address (from relay's perspective)")
	verbose          = flag.Bool("v", false, "Show per-worker errors")
	sni              = flag.String("sni", "cloudflare.com", "SNI for TLS handshake")
	userID           = flag.String("user-id", "throughput-test-00000000-0000-0000-0000-000000000001", "User ID for auth")
	cmdDownload byte = 'D'
	cmdUpload   byte = 'U'
)

type counters struct {
	dlBytes  atomic.Int64
	ulBytes  atomic.Int64
	dlErrors atomic.Int64
	ulErrors atomic.Int64
	dlConns  atomic.Int64
	ulConns  atomic.Int64
}

// encodeTrace 是一个无锁的近期 encode (seq, sha256) 记录环形缓冲区，
// 用于与中继端 AEAD 失败进行交叉验证。
type encodeTrace struct {
	entries []encodeEntry
	mask    int
	pos     atomic.Int64
}

type encodeEntry struct {
	seq uint64
	sum [32]byte
}

func newEncodeTrace(n int) *encodeTrace {
	size := 1
	for size < n {
		size <<= 1
	}
	return &encodeTrace{
		entries: make([]encodeEntry, size),
		mask:    size - 1,
	}
}

func (t *encodeTrace) add(seq uint64, sum [32]byte) {
	i := int(t.pos.Add(1)) & t.mask
	t.entries[i].seq = seq
	t.entries[i].sum = sum
}

func (t *encodeTrace) dump() string {
	end := int(t.pos.Load())
	start := end - len(t.entries)
	if start < 0 {
		start = 0
	}
	var lines []string
	for i := start; i <= end; i++ {
		e := &t.entries[i&t.mask]
		if e.seq != 0 || e.sum != [32]byte{} {
			lines = append(lines, fmt.Sprintf("  seq=%d sha256=%064x", e.seq, e.sum))
		}
	}
	return strings.Join(lines, "\n")
}

func dlWorker(id int, dialer *chimney.Dialer, ctx context.Context, c *counters, wg *sync.WaitGroup, bufsz int) {
	defer wg.Done()
	buf := make([]byte, bufsz)
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := dialer.DialContext(ctx, "tcp", *backend)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.dlErrors.Add(1)
			if *verbose {
				log.Printf("[DL#%d] dial: %v", id, err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		c.dlConns.Add(1)
		if _, err := conn.Write([]byte{cmdDownload}); err != nil {
			conn.Close()
			c.dlErrors.Add(1)
			continue
		}
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				c.dlBytes.Add(int64(n))
			}
			if err != nil {
				if ctx.Err() == nil {
					c.dlErrors.Add(1)
					if *verbose {
						log.Printf("[DL#%d] read: %v", id, err)
					}
				}
				break
			}
		}
		conn.Close()
	}
}

func ulWorker(id int, dialer *chimney.Dialer, ctx context.Context, c *counters, wg *sync.WaitGroup, bufsz int) {
	defer wg.Done()
	buf := make([]byte, bufsz)
	rand.Read(buf)
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := dialer.DialContext(ctx, "tcp", *backend)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.ulErrors.Add(1)
			if *verbose {
				log.Printf("[UL#%d] dial: %v", id, err)
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		c.ulConns.Add(1)
		if _, err := conn.Write([]byte{cmdUpload}); err != nil {
			conn.Close()
			c.ulErrors.Add(1)
			continue
		}
		for {
			if ctx.Err() != nil {
				conn.Close()
				return
			}
			n, err := conn.Write(buf)
			if n > 0 {
				c.ulBytes.Add(int64(n))
			}
			if err != nil {
				if ctx.Err() == nil {
					c.ulErrors.Add(1)
					if *verbose {
						log.Printf("[UL#%d] write: %v", id, err)
					}
				}
				break
			}
		}
		conn.Close()
	}
}

func reporter(ctx context.Context, c *counters, interval time.Duration, startTime time.Time) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var prevDL, prevUL int64
	prevTime := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			dt := t.Sub(prevTime).Seconds()
			curDL := c.dlBytes.Load()
			curUL := c.ulBytes.Load()
			dlRate := float64(curDL-prevDL) * 8 / dt / 1e6
			ulRate := float64(curUL-prevUL) * 8 / dt / 1e6
			fmt.Printf("\r[%5.1fs]  下载: %6.1f Mbps  上传: %6.1f Mbps  连接: dl=%d ul=%d  错误: dl=%d ul=%d    ",
				t.Sub(startTime).Seconds(),
				dlRate, ulRate,
				c.dlConns.Load(), c.ulConns.Load(),
				c.dlErrors.Load(), c.ulErrors.Load(),
			)
			prevDL = curDL
			prevUL = curUL
			prevTime = t
		}
	}
}

func main() {
	flag.Parse()
	if *relayAddr == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -relay <host:port> [...]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	traceBuf := newEncodeTrace(4096)
	record.RecordTraceHook = func(dir string, seq uint64, recordData []byte, keyFP [4]byte) {
		if dir == "encode" {
			sum := sha256.Sum256(recordData)
			traceBuf.add(seq, sum)
			fmt.Fprintf(os.Stderr, "[trace] seq=%d sha256=%064x\n", seq, sum)
		}
	}

	dialer, err := chimney.NewDialer(chimney.Config{
		RelayAddr:   *relayAddr,
		SNI:         *sni,
		UserID:      *userID,
		TagLen:      16,
		Fingerprint: "chrome",
		PoolSize:    *poolSize,
	})
	if err != nil {
		log.Fatalf("dialer: %v", err)
	}
	defer dialer.Close()

	fmt.Printf("Relay: %s  SNI: %s  Backend: %s\n", *relayAddr, *sni, *backend)
	fmt.Printf("配置: dl_workers=%d  ul_workers=%d  pool=%d  buf=%dKB  duration=%s\n",
		*dlWorkers, *ulWorkers, *poolSize, *bufSize/1024, *duration)
	fmt.Printf("等待连接池预热...\n")
	time.Sleep(1 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	startTime := time.Now()
	var c counters
	var wg sync.WaitGroup

	for i := 0; i < *dlWorkers; i++ {
		wg.Add(1)
		go dlWorker(i, dialer, ctx, &c, &wg, *bufSize)
	}
	for i := 0; i < *ulWorkers; i++ {
		wg.Add(1)
		go ulWorker(i, dialer, ctx, &c, &wg, *bufSize)
	}

	go reporter(ctx, &c, time.Second, startTime)
	wg.Wait()

	elapsed := time.Since(startTime).Seconds()
	totalDL := c.dlBytes.Load()
	totalUL := c.ulBytes.Load()
	fmt.Printf("\n\n=== 测试结果 ===\n")
	fmt.Printf("持续时间:    %.1fs\n", elapsed)
	fmt.Printf("总下载:      %.1f MB  (平均 %.1f Mbps)\n",
		float64(totalDL)/1e6, float64(totalDL)*8/elapsed/1e6)
	fmt.Printf("总上传:      %.1f MB  (平均 %.1f Mbps)\n",
		float64(totalUL)/1e6, float64(totalUL)*8/elapsed/1e6)
	fmt.Printf("下载连接数:  %d  (错误 %d)\n", c.dlConns.Load(), c.dlErrors.Load())
	fmt.Printf("上传连接数:  %d  (错误 %d)\n", c.ulConns.Load(), c.ulErrors.Load())
	fmt.Printf("\n最近 encode trace (seq -> sha256):\n%s\n", traceBuf.dump())
	if err := dialer.LastError(); err != nil {
		fmt.Printf("Dialer 最后错误: %v\n", err)
	}
	fmt.Printf("\nDiagnostics:\n%s\n", dialer.Diagnostics())
}
