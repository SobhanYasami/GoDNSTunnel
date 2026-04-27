// Command relayvpn starts the local HTTP+SOCKS5 proxy that domain-
// fronts traffic through a Google Apps Script relay.
//
// Usage:
//
//	relayvpn -c config.json
//	DFT_AUTH_KEY=... relayvpn      (env override)
//
// On first run it generates an ECDSA P-256 CA at ./ca/ca.{crt,key};
// install ca.crt as a trusted root locally so HTTPS sites validate.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/auth"
	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/config"
	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/mitm"
	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/proxy"
	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/relay"
)

func main() {
	var (
		cfgPath = flag.String("c", "config.json", "path to config.json")
		caDir   = flag.String("ca-dir", "ca", "directory for CA cert and key")
	)
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	// Env overrides (preserves the upstream DFT_* convention).
	if v := os.Getenv("DFT_AUTH_KEY"); v != "" {
		cfg.AuthKey = v
		if err := cfg.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "config (env override):", err)
			os.Exit(2)
		}
	}

	logger := newLogger(cfg.LogLevel)

	ca, err := mitm.LoadOrCreate(*caDir)
	if err != nil {
		logger.Error("CA init", "err", err)
		os.Exit(1)
	}
	caPath, _ := filepath.Abs(filepath.Join(*caDir, "ca.crt"))
	logger.Info("CA ready", "cert", caPath, "fingerprint", certFingerprint(ca.CertDER))

	mint := mitm.NewMint(ca)

	rc, err := relay.NewClient(relay.ClientConfig{
		GoogleIP:        cfg.GoogleIP,
		FrontDomain:     cfg.FrontDomain,
		ScriptIDs:       cfg.AllScriptIDs(),
		SigningKey:      []byte(cfg.AuthKey),
		TLSConnectTO:    cfg.TLSConnectTimeout(),
		RelayTimeout:    cfg.RelayTimeout(),
		MaxResponseBody: cfg.MaxResponseBodyB,
	})
	if err != nil {
		logger.Error("relay client", "err", err)
		os.Exit(1)
	}

	gate := auth.New(cfg.ProxyUser, cfg.ProxyPass)

	httpAddr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(int(cfg.ListenPort)))
	socksAddr := ""
	if cfg.SOCKS5On {
		socksAddr = net.JoinHostPort(cfg.ListenHost, strconv.Itoa(int(cfg.SOCKS5Port)))
	}

	srv := &proxy.Server{
		Addr:        httpAddr,
		SOCKS5Addr:  socksAddr,
		Auth:        gate,
		Mint:        mint,
		Relay:       rc,
		BlockHosts:  cfg.BlockHosts,
		BypassHosts: cfg.BypassHosts,
		Logger:      logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		logger.Error("proxy", "err", err)
		os.Exit(1)
	}
	logger.Info("shutdown clean")
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// certFingerprint returns the lowercase hex SHA-256 of the DER cert.
// Compare against the "SHA-256 thumbprint" in your OS / browser cert
// store to confirm the trusted root matches what the proxy is using.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
