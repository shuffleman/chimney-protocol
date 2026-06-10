// cmd/chimney-relay 是 Chimney 中继服务器。
//
// 中继是 Chimney 协议的核心组件。它位于
// 客户端和真实互联网之间，将 TLS 握手转发到真实站点
// 并在成功认证后接管连接。
//
// 用法：
//
//	chimney-relay -config /path/to/config.yaml
//
// 配置文件指定：
//   - 监听地址
//   - PSK（预共享密钥）
//   - 白名单文件（intent + enforce 层）
//   - 云区域（用于 CIDR 验证）
//   - TLS-in-TLS 整形参数
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/config"
	"github.com/shuffleman/chimney-protocol/internal/relay"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config/relay.yaml", "Path to relay configuration file")
	flag.Parse()

	// 设置结构化日志
	logLevel := &slog.LevelVar{}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// 从 YAML 加载配置
	cfg, err := config.LoadRelayConfig(configPath)
	if err != nil {
		logger.Warn("failed to load configuration, using defaults", "error", err)
		cfg = config.DefaultRelayConfig()
	}

	// 从配置中设置日志级别
	switch cfg.LogLevel {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}

	// 转换为中继配置
	relayConfig := &relay.Config{
		ListenAddr:         cfg.ListenAddr,
		PSK:                cfg.PSK,
		Users:              cfg.Users,
		UserIDs:            cfg.UserIDs,
		TagLen:             cfg.TagLen,
		IntentFile:         cfg.IntentFile,
		EnforceFile:        cfg.EnforceFile,
		CloudRegion:        cfg.CloudRegion,
		DefaultBackend:     cfg.DefaultBackend,
		HandshakeTimeout:   cfg.HandshakeTimeout,
		AuthReadTimeout:    cfg.AuthReadTimeout,
		EnableProfiling:    cfg.EnableProfiling,
		ProfileDir:         cfg.ProfileDir,
		ConnectAllowCIDRs:  cfg.ConnectAllowCIDRs,
		ConnectDenyCIDRs:   cfg.ConnectDenyCIDRs,
		ConnectDenyPrivate: cfg.ConnectDenyPrivate,

		StealthMode:         cfg.StealthMode,
		DownlinkLevel:       cfg.DownlinkLevel,
		DownlinkRecordSize:  cfg.DownlinkRecordSize,
		DownlinkRatioTarget: cfg.DownlinkRatioTarget,
	}

	// 创建并启动中继服务器
	server, err := relay.NewServer(relayConfig, logger)
	if err != nil {
		logger.Error("failed to create relay server", "error", err)
		os.Exit(1)
	}

	if err := server.Start(); err != nil {
		logger.Error("failed to start relay server", "error", err)
		os.Exit(1)
	}

	logger.Info("chimney relay started",
		"listen", cfg.ListenAddr,
		"cloud_region", cfg.CloudRegion,
	)

	// 如果配置了 metrics 地址，启动管理 API
	if cfg.MetricsAddr != "" {
		adminToken := cfg.MetricsToken
		if adminToken == "" {
			adminToken = os.Getenv("CHIMNEY_ADMIN_TOKEN")
		}
		go startAdminAPI(cfg.MetricsAddr, adminToken, server, logger)
	}

	// 等待中断信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 定期打印统计信息
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigCh:
			logger.Info("received signal, shutting down", "signal", sig)
			if err := server.Stop(); err != nil {
				logger.Error("error during shutdown", "error", err)
			}
			logger.Info("shutdown complete")
			return

		case <-ticker.C:
			stats := server.Stats()
			logger.Info("relay statistics",
				"total_connections", stats.TotalConnections.Load(),
				"active_connections", stats.ActiveConnections.Load(),
				"authenticated_swaps", stats.AuthenticatedSwaps.Load(),
				"auth_failures", stats.AuthFailures.Load(),
				"whitelist_rejections", stats.WhitelistRejections.Load(),
				"bytes_up", stats.RelayBytesUp.Load(),
				"bytes_down", stats.RelayBytesDown.Load(),
			)
		}
	}
}

// startAdminAPI 启动一个用于指标和管理操作的极简 HTTP 服务器。
func startAdminAPI(addr, adminToken string, server *relay.Server, logger *slog.Logger) {
	mux := http.NewServeMux()
	requireAdmin := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !adminAuthorized(r, adminToken) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/admin/stats", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		stats := server.Stats()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
  "total_connections": %d,
  "active_connections": %d,
  "authenticated_swaps": %d,
  "auth_failures": %d,
  "whitelist_rejections": %d,
  "bytes_up": %d,
  "bytes_down": %d
}`,
			stats.TotalConnections.Load(),
			stats.ActiveConnections.Load(),
			stats.AuthenticatedSwaps.Load(),
			stats.AuthFailures.Load(),
			stats.WhitelistRejections.Load(),
			stats.RelayBytesUp.Load(),
			stats.RelayBytesDown.Load(),
		)
	}))

	mux.HandleFunc("/admin/refresh-cidrs", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "ok", "message": "CIDR refresh triggered"}`)
	}))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	// ── 动态用户管理 ──────────────────────────────
	mux.HandleFunc("/admin/users", requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		us := server.UserStore()
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			ids := us.ListUserIDs()
			json.NewEncoder(w).Encode(map[string]any{
				"user_ids": ids,
				"count":    len(ids),
			})

		case http.MethodPost:
			var req struct {
				UserID string `json:"user_id"`
				PSK    string `json:"psk,omitempty"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON: " + err.Error()})
				return
			}
			if req.UserID == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "user_id is required"})
				return
			}
			if err := us.AddUser(req.UserID, req.PSK); err != nil {
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "user_id": req.UserID})

		case http.MethodDelete:
			var req struct {
				UserID string `json:"user_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON: " + err.Error()})
				return
			}
			if req.UserID == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "user_id is required"})
				return
			}
			if err := us.RemoveUserByID(req.UserID); err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "user_id": req.UserID})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		}
	}))

	if adminToken == "" {
		logger.Warn("admin API token is empty; /admin endpoints are restricted to loopback clients only", "addr", addr)
	}
	logger.Info("admin API listening", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("admin API failed", "error", err)
	}
}

func adminAuthorized(r *http.Request, adminToken string) bool {
	if adminToken != "" {
		authz := r.Header.Get("Authorization")
		if strings.HasPrefix(authz, "Bearer ") && tokenEqual(strings.TrimSpace(strings.TrimPrefix(authz, "Bearer ")), adminToken) {
			return true
		}
		return tokenEqual(r.Header.Get("X-Admin-Token"), adminToken)
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func tokenEqual(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
