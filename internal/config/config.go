// Package config loads and validates the on-disk JSON config.
//
// Strict semantics: unknown fields are rejected, defaults are applied
// after parse, and structural constraints are checked before any listener
// or transport is constructed. This replaces the upstream pattern of
// `config.get(...)` scattered across modules where typos silently pass.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
)

// Config is the on-disk schema. Field names match the JSON keys the
// upstream Python project uses, so existing config.json files keep working.
type Config struct {
	Mode        string `json:"mode"`         // only "apps_script" supported
	GoogleIP    string `json:"google_ip"`    // fronted endpoint (parsed as netip.Addr)
	FrontDomain string `json:"front_domain"` // SNI sent to Google
	ScriptID    string `json:"script_id"`    // single deployment ID
	ScriptIDs   []string `json:"script_ids"` // optional load-balancing pool

	// Shared secret with the Apps Script relay. Used as HMAC key.
	// Must be ≥32 random bytes when base64'd, or ≥24 chars otherwise.
	AuthKey string `json:"auth_key"`

	// Local listeners.
	ListenHost   string `json:"listen_host"`
	ListenPort   uint16 `json:"listen_port"`
	SOCKS5On     bool   `json:"socks5_enabled"`
	SOCKS5Port   uint16 `json:"socks5_port"`
	LANSharing   bool   `json:"lan_sharing"`

	// Proxy auth gate. If empty AND listening on loopback, gate is disabled.
	// If LANSharing is true, ProxyUser/ProxyPass MUST be set.
	ProxyUser string `json:"proxy_user"`
	ProxyPass string `json:"proxy_pass"`

	LogLevel string `json:"log_level"` // debug|info|warn|error

	RelayTimeoutSec     int   `json:"relay_timeout"`
	TLSConnectTimeoutS  int   `json:"tls_connect_timeout"`
	TCPConnectTimeoutS  int   `json:"tcp_connect_timeout"`
	MaxResponseBodyB    int64 `json:"max_response_body_bytes"`

	BlockHosts        []string          `json:"block_hosts"`
	BypassHosts       []string          `json:"bypass_hosts"`
	HostsOverride     map[string]string `json:"hosts"`
	YouTubeViaRelay   bool              `json:"youtube_via_relay"`
}

const (
	minAuthKeyLen = 24
)

// Defaults are conservative: loopback only, no LAN sharing, MITM safe knobs.
func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = "apps_script"
	}
	if c.ListenHost == "" {
		c.ListenHost = "127.0.0.1"
	}
	if c.ListenPort == 0 {
		c.ListenPort = 8085
	}
	if c.SOCKS5Port == 0 {
		c.SOCKS5Port = 1080
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.RelayTimeoutSec == 0 {
		c.RelayTimeoutSec = 25
	}
	if c.TLSConnectTimeoutS == 0 {
		c.TLSConnectTimeoutS = 15
	}
	if c.TCPConnectTimeoutS == 0 {
		c.TCPConnectTimeoutS = 10
	}
	if c.MaxResponseBodyB == 0 {
		c.MaxResponseBodyB = 200 << 20 // 200 MiB
	}
	if c.FrontDomain == "" {
		c.FrontDomain = "www.google.com"
	}
	if c.GoogleIP == "" {
		c.GoogleIP = "216.239.38.120"
	}
	if len(c.BypassHosts) == 0 {
		c.BypassHosts = []string{"localhost", ".local", ".lan", ".home.arpa"}
	}
}

// Validate enforces structural and security invariants. Returns the
// first violation; we don't aggregate because the user fixes them
// one-at-a-time anyway.
func (c *Config) Validate() error {
	if c.Mode != "apps_script" {
		return fmt.Errorf("mode %q not supported (only apps_script)", c.Mode)
	}
	if _, err := netip.ParseAddr(c.GoogleIP); err != nil {
		return fmt.Errorf("google_ip: %w", err)
	}
	if !validHostname(c.FrontDomain) {
		return fmt.Errorf("front_domain %q is not a valid hostname", c.FrontDomain)
	}
	if c.ScriptID == "" && len(c.ScriptIDs) == 0 {
		return errors.New("script_id (or script_ids[]) is required")
	}
	for _, id := range append([]string{c.ScriptID}, c.ScriptIDs...) {
		if id == "" {
			continue
		}
		// Apps Script deployment IDs are url-safe alphanumerics, ~57 chars.
		if len(id) < 32 || strings.ContainsAny(id, " /\\?#") {
			return fmt.Errorf("script_id %q is malformed", id)
		}
	}
	if len(c.AuthKey) < minAuthKeyLen {
		return fmt.Errorf("auth_key must be ≥%d chars (current: %d)", minAuthKeyLen, len(c.AuthKey))
	}
	if c.AuthKey == "CHANGE_ME_TO_A_STRONG_SECRET" {
		return errors.New("auth_key is still the example placeholder")
	}
	if c.ListenPort == c.SOCKS5Port && c.SOCKS5On {
		return fmt.Errorf("listen_port and socks5_port collide (%d)", c.ListenPort)
	}
	if c.LANSharing {
		// Force a non-loopback listen, AND require auth.
		if isLoopback(c.ListenHost) {
			c.ListenHost = "0.0.0.0"
		}
		if c.ProxyUser == "" || c.ProxyPass == "" {
			return errors.New("lan_sharing=true requires proxy_user and proxy_pass")
		}
	}
	if !validLogLevel(c.LogLevel) {
		return fmt.Errorf("log_level %q invalid", c.LogLevel)
	}
	return nil
}

func (c Config) RelayTimeout() time.Duration   { return time.Duration(c.RelayTimeoutSec) * time.Second }
func (c Config) TLSConnectTimeout() time.Duration { return time.Duration(c.TLSConnectTimeoutS) * time.Second }
func (c Config) TCPConnectTimeout() time.Duration { return time.Duration(c.TCPConnectTimeoutS) * time.Second }

// AllScriptIDs returns ScriptIDs ∪ {ScriptID}, de-duplicated, in order.
func (c Config) AllScriptIDs() []string {
	seen := make(map[string]struct{}, len(c.ScriptIDs)+1)
	out := make([]string, 0, len(c.ScriptIDs)+1)
	for _, id := range append([]string{c.ScriptID}, c.ScriptIDs...) {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// Load reads and validates a config file at path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads and validates a config from any reader.
func Parse(r io.Reader) (*Config, error) {
	var c Config
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields() // typo'd keys fail loudly
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config decode: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func validHostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, lbl := range strings.Split(s, ".") {
		if lbl == "" || len(lbl) > 63 {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
	}
	return true
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func validLogLevel(s string) bool {
	switch strings.ToLower(s) {
	case "debug", "info", "warn", "warning", "error":
		return true
	}
	return false
}
