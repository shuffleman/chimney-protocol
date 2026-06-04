package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	chimney "github.com/shuffleman/chimney-protocol"
)

type hostAddr struct {
	network string
	address string
}

func (a hostAddr) Network() string { return a.network }
func (a hostAddr) String() string  { return a.address }

type result struct {
	RelayAddr    string `json:"relay_addr"`
	Target       string `json:"target"`
	QueryName    string `json:"query_name"`
	Workers      int    `json:"workers"`
	Count        int    `json:"count"`
	Sent         int64  `json:"sent"`
	Received     int64  `json:"received"`
	Errors       int64  `json:"errors"`
	ElapsedMS    int64  `json:"elapsed_ms"`
	AverageRTTMS int64  `json:"average_rtt_ms"`
}

func main() {
	var (
		relayAddr   = flag.String("relay", "127.0.0.1:8444", "Chimney relay address")
		sni         = flag.String("sni", "cloudflare.com", "TLS SNI allowed by the relay")
		psk         = flag.String("psk", "", "64-character hex PSK")
		userID      = flag.String("user-id", "", "user ID used to derive PSK when -psk is empty")
		fingerprint = flag.String("fingerprint", "chrome", "uTLS fingerprint")
		target      = flag.String("target", "1.1.1.1:53", "UDP DNS target, IP or domain host:port")
		queryName   = flag.String("query", "cloudflare.com", "DNS A query name")
		workers     = flag.Int("workers", 4, "parallel PacketConn workers")
		count       = flag.Int("count", 20, "queries per worker")
		timeout     = flag.Duration("timeout", 5*time.Second, "per-query timeout")
		poolSize    = flag.Int("pool-size", 4, "Chimney tunnel pool size")
		jsonOutput  = flag.Bool("json", false, "print machine-readable JSON")
	)
	flag.Parse()

	if *workers <= 0 || *count <= 0 {
		exitf("workers and count must be positive")
	}
	if *psk == "" && *userID == "" {
		exitf("either -psk or -user-id is required")
	}

	dst, err := udpTargetAddr(*target)
	if err != nil {
		exitf("invalid target: %v", err)
	}

	dialer, err := chimney.NewDialer(chimney.Config{
		RelayAddr:     *relayAddr,
		SNI:           *sni,
		PSK:           *psk,
		UserID:        *userID,
		Fingerprint:   *fingerprint,
		PoolSize:      *poolSize,
		TCPBufferSize: 64 * 1024,
	})
	if err != nil {
		exitf("create chimney dialer: %v", err)
	}
	defer dialer.Close()

	var sent, received, failures, totalRTT atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	for workerID := 0; workerID < *workers; workerID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			pc, err := dialer.ListenPacket(context.Background())
			if err != nil {
				failures.Add(int64(*count))
				return
			}
			defer pc.Close()

			for i := 0; i < *count; i++ {
				id, query, err := dnsAQuery(*queryName)
				if err != nil {
					failures.Add(1)
					continue
				}
				if err := pc.SetDeadline(time.Now().Add(*timeout)); err != nil {
					failures.Add(1)
					continue
				}

				t0 := time.Now()
				if _, err := pc.WriteTo(query, dst); err != nil {
					failures.Add(1)
					continue
				}
				sent.Add(1)

				buf := make([]byte, 1500)
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					failures.Add(1)
					continue
				}
				if err := validateDNSResponse(buf[:n], id); err != nil {
					failures.Add(1)
					continue
				}
				received.Add(1)
				totalRTT.Add(time.Since(t0).Milliseconds())
			}
		}(workerID)
	}
	wg.Wait()

	elapsed := time.Since(start)
	out := result{
		RelayAddr: *relayAddr,
		Target:    *target,
		QueryName: *queryName,
		Workers:   *workers,
		Count:     *count,
		Sent:      sent.Load(),
		Received:  received.Load(),
		Errors:    failures.Load(),
		ElapsedMS: elapsed.Milliseconds(),
	}
	if out.Received > 0 {
		out.AverageRTTMS = totalRTT.Load() / out.Received
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			exitf("write json: %v", err)
		}
	} else {
		fmt.Printf("relay=%s target=%s query=%s workers=%d count=%d\n", out.RelayAddr, out.Target, out.QueryName, out.Workers, out.Count)
		fmt.Printf("sent=%d received=%d errors=%d elapsed=%s avg_rtt=%dms\n", out.Sent, out.Received, out.Errors, elapsed.Round(time.Millisecond), out.AverageRTTMS)
	}
	if out.Errors > 0 || out.Received != int64(*workers**count) {
		os.Exit(1)
	}
}

func udpTargetAddr(target string) (net.Addr, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			return nil, err
		}
		return addr, nil
	}
	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("domain length must be 1..255")
	}
	return hostAddr{network: "udp", address: net.JoinHostPort(host, port)}, nil
}

func dnsAQuery(name string) (uint16, []byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return 0, nil, fmt.Errorf("query name is empty")
	}
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])

	msg := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return 0, nil, fmt.Errorf("invalid DNS label %q", label)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 1) // A
	msg = binary.BigEndian.AppendUint16(msg, 1) // IN
	return id, msg, nil
}

func validateDNSResponse(msg []byte, id uint16) error {
	if len(msg) < 12 {
		return fmt.Errorf("short DNS response")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != id {
		return fmt.Errorf("DNS transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return fmt.Errorf("DNS response bit not set")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return fmt.Errorf("DNS response rcode=%d", rcode)
	}
	if binary.BigEndian.Uint16(msg[6:8]) == 0 {
		return fmt.Errorf("DNS response has no answers")
	}
	return nil
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "udp_stress: "+format+"\n", args...)
	os.Exit(2)
}
