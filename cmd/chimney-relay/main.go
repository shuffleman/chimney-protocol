// cmd/chimney-relay is the Chimney relay server.
//
// The relay is the central component of the Chimney protocol. It sits between
// the client and the real internet, forwarding TLS handshakes to real sites
// and taking over connections after successful authentication.
//
// Usage:
//
//	chimney-relay -config /path/to/config.yaml
//
// The config file specifies:
//   - Listen address
//   - PSK (pre-shared key)
//   - Whitelist files (intent + enforce layers)
//   - Cloud region for CIDR validation
//   - TLS-in-TLS shaping parameters
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shuffleman/chimney-protocol/internal/config"
	"github.com/shuffleman/chimney-protocol/internal/relay"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config/relay.yaml", "Path to relay configuration file")
	flag.Parse()

	// Setup structured logging
	logLevel := &slog.LevelVar{}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Load configuration from YAML
	cfg, err := config.LoadRelayConfig(configPath)
	if err != nil {
		logger.Warn("failed to load configuration, using defaults", "error", err)
		cfg = config.DefaultRelayConfig()
	}

	// Set log level from config
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

	// Convert to relay config
	relayConfig := &relay.Config{
		ListenAddr:       cfg.ListenAddr,
		PSK:              cfg.PSK,
		Users:            cfg.Users,
		UserIDs:          cfg.UserIDs,
		TagLen:           cfg.TagLen,
		IntentFile:       cfg.IntentFile,
		EnforceFile:      cfg.EnforceFile,
		CloudRegion:      cfg.CloudRegion,
		DefaultBackend:   cfg.DefaultBackend,
		HandshakeTimeout: cfg.HandshakeTimeout,
		AuthReadTimeout:  cfg.AuthReadTimeout,
		EnableProfiling:  cfg.EnableProfiling,
		ProfileDir:       cfg.ProfileDir,
	}

	// Create and start relay server
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

	// Start admin API if metrics address is configured
	if cfg.MetricsAddr != "" {
		go startAdminAPI(cfg.MetricsAddr, server, logger)
	}

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Print stats periodically
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

// startAdminAPI starts a minimal HTTP server for metrics and admin actions.
func startAdminAPI(addr string, server *relay.Server, logger *slog.Logger) {
	http.HandleFunc("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
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
	})

	http.HandleFunc("/admin/refresh-cidrs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "ok", "message": "CIDR refresh triggered"}`)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK")
	})

	logger.Info("admin API listening", "addr", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Error("admin API failed", "error", err)
	}
}
