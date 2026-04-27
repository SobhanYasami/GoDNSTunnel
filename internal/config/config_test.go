package config

import (
	"strings"
	"testing"
)

func goodConfigJSON() string {
	return `{
		"mode": "apps_script",
		"google_ip": "216.239.38.120",
		"front_domain": "www.google.com",
		"script_id": "AKfycbz0123456789abcdef0123456789abcdef0123",
		"auth_key": "x9-some-strong-secret-of-sufficient-length",
		"listen_host": "127.0.0.1",
		"listen_port": 8085,
		"socks5_enabled": true,
		"socks5_port": 1080,
		"log_level": "info"
	}`
}

func TestParseGood(t *testing.T) {
	c, err := Parse(strings.NewReader(goodConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if c.RelayTimeout().Seconds() != 25 {
		t.Errorf("expected default relay_timeout=25s, got %v", c.RelayTimeout())
	}
}

func TestRejectUnknownField(t *testing.T) {
	mod := strings.Replace(goodConfigJSON(), `"log_level": "info"`,
		`"log_level": "info", "lol_typo": 1`, 1)
	_, err := Parse(strings.NewReader(mod))
	if err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestRejectShortAuthKey(t *testing.T) {
	mod := strings.Replace(goodConfigJSON(),
		`"x9-some-strong-secret-of-sufficient-length"`,
		`"too-short"`, 1)
	_, err := Parse(strings.NewReader(mod))
	if err == nil || !strings.Contains(err.Error(), "auth_key") {
		t.Fatalf("expected auth_key length error, got %v", err)
	}
}

func TestRejectPlaceholderAuthKey(t *testing.T) {
	mod := strings.Replace(goodConfigJSON(),
		`"x9-some-strong-secret-of-sufficient-length"`,
		`"CHANGE_ME_TO_A_STRONG_SECRET"`, 1)
	_, err := Parse(strings.NewReader(mod))
	if err == nil {
		t.Fatal("placeholder auth_key must be rejected")
	}
}

func TestPortCollision(t *testing.T) {
	mod := strings.Replace(goodConfigJSON(),
		`"socks5_port": 1080`,
		`"socks5_port": 8085`, 1)
	_, err := Parse(strings.NewReader(mod))
	if err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("expected collision error, got %v", err)
	}
}

func TestLANSharingRequiresAuth(t *testing.T) {
	mod := strings.Replace(goodConfigJSON(),
		`"log_level": "info"`,
		`"log_level": "info", "lan_sharing": true`, 1)
	_, err := Parse(strings.NewReader(mod))
	if err == nil || !strings.Contains(err.Error(), "proxy_user") {
		t.Fatalf("expected LAN-without-auth rejection, got %v", err)
	}
}

func TestLANSharingWithAuthOK(t *testing.T) {
	mod := strings.Replace(goodConfigJSON(),
		`"log_level": "info"`,
		`"log_level": "info", "lan_sharing": true, "proxy_user": "u", "proxy_pass": "p"`, 1)
	c, err := Parse(strings.NewReader(mod))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenHost == "127.0.0.1" {
		t.Errorf("LAN sharing should rebind off loopback, got %q", c.ListenHost)
	}
}
