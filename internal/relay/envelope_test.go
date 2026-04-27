package relay

import (
	"bytes"
	"testing"
	"time"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	key := []byte("a-strong-shared-secret-for-testing-only")
	r := Request{
		Method:      "POST",
		URL:         "https://api.example.com/echo?x=1",
		Headers:     map[string]string{"User-Agent": "ua/1", "X-Trace": "abc"},
		Body:        []byte(`{"hello":"world"}`),
		ContentType: "application/json",
		Redirect:    true,
	}
	env, err := Build(key, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(key, env); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	key := []byte("a-strong-shared-secret-for-testing-only")
	env, err := Build(key, Request{Method: "GET", URL: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		mut   func(*Envelope)
	}{
		{"method", func(e *Envelope) { e.M = "POST" }},
		{"url", func(e *Envelope) { e.U = "https://evil.example.com/" }},
		{"ts", func(e *Envelope) { e.TS++ }},
		{"nonce", func(e *Envelope) { e.N = "AAAAAAAAAAAAAAAAAAAAAA==" }},
		{"redirect", func(e *Envelope) { e.R = !e.R }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp := *env
			c.mut(&cp)
			if err := Verify(key, &cp); err == nil {
				t.Fatalf("tampered %s passed verification", c.name)
			}
		})
	}
}

func TestSkewWindow(t *testing.T) {
	key := []byte("a-strong-shared-secret-for-testing-only")
	env, err := Build(key, Request{Method: "GET", URL: "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the request is from 10 minutes ago. Re-sign to keep the
	// HMAC valid, then ensure Verify rejects on freshness alone.
	env.TS -= (10 * time.Minute).Milliseconds()
	env.Sig = sign(key, env)
	if err := Verify(key, env); err == nil {
		t.Fatal("stale envelope should be rejected on skew")
	}
}

func TestCanonicalHeadersStable(t *testing.T) {
	a := canonicalHeaders(map[string]string{"X-Foo": "1", "Y-Bar": "2"})
	b := canonicalHeaders(map[string]string{"y-bar": "2", "x-foo": "1"})
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical headers differ: %s vs %s", a, b)
	}
}
