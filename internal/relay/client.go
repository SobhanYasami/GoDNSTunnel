package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Client speaks to one or more Apps Script deployments via domain
// fronting: TCP to googleIP, TLS handshake with SNI=frontDomain,
// HTTP request with Host=script.google.com. The path includes the
// deployment ID; we round-robin across multiple IDs if configured.
//
// IMPORTANT: verify_ssl is no longer configurable. The local fronted
// leg always validates the certificate. The upstream Python project
// exposed `verify_ssl: bool` and users routinely flipped it to false
// to "fix" issues, leaving the link MITM-able.
type Client struct {
	hc          *http.Client
	signingKey  []byte
	scriptIDs   []string
	rrCounter   uint64
	maxRespBody int64
}

type ClientConfig struct {
	GoogleIP        string
	FrontDomain     string
	ScriptIDs       []string
	SigningKey      []byte
	TLSConnectTO    time.Duration
	RelayTimeout    time.Duration
	MaxResponseBody int64
}

func NewClient(cc ClientConfig) (*Client, error) {
	if len(cc.ScriptIDs) == 0 {
		return nil, errors.New("relay: no script IDs")
	}
	if len(cc.SigningKey) < 24 {
		return nil, errors.New("relay: signing key too short")
	}
	if cc.GoogleIP == "" || cc.FrontDomain == "" {
		return nil, errors.New("relay: GoogleIP and FrontDomain required")
	}
	dialer := &net.Dialer{
		Timeout:   cc.TLSConnectTO,
		KeepAlive: 30 * time.Second,
	}
	tlsCfg := &tls.Config{
		ServerName: cc.FrontDomain,
		MinVersion: tls.VersionTLS12,
		// The relay terminates TLS at script.google.com via the
		// fronted SNI; we still validate against the front cert.
	}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cc.GoogleIP, "443"))
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: cc.RelayTimeout,
		TLSHandshakeTimeout:   cc.TLSConnectTO,
		ExpectContinueTimeout: 0,
		DisableCompression:    true, // we handle codec ourselves
	}
	return &Client{
		hc:          &http.Client{Transport: tr, Timeout: cc.RelayTimeout},
		signingKey:  cc.SigningKey,
		scriptIDs:   append([]string(nil), cc.ScriptIDs...),
		maxRespBody: cc.MaxResponseBody,
	}, nil
}

// Response is the relay's reply: HTTP status, headers, and body
// from the origin server.
type Response struct {
	Status  int               `json:"s"`
	Headers map[string]any    `json:"h"`
	Body    []byte            `json:"-"` // decoded from b64
	Error   string            `json:"e,omitempty"`
}

type wireResp struct {
	Status  int            `json:"s"`
	Headers map[string]any `json:"h"`
	B       string         `json:"b"`
	Error   string         `json:"e"`
}

// Do issues a relayed request. ctx controls the overall deadline.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	env, err := Build(c.signingKey, r)
	if err != nil {
		return nil, err
	}
	body, err := env.Marshal()
	if err != nil {
		return nil, err
	}

	scriptID := c.pickScriptID()
	url := "https://script.google.com/macros/s/" + scriptID + "/exec"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = "script.google.com" // explicit, despite URL — guards against rewriters
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Apps Script counts request bodies against quota; no need to
	// inflate them with random User-Agent strings.
	req.Header.Set("User-Agent", "Mozilla/5.0")

	httpResp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay POST: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// Drain a small prefix for diagnostic logging upstream.
		head, _ := io.ReadAll(io.LimitReader(httpResp.Body, 512))
		return nil, fmt.Errorf("relay HTTP %d: %s", httpResp.StatusCode, head)
	}

	limited := io.LimitReader(httpResp.Body, c.maxRespBody+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > c.maxRespBody {
		return nil, fmt.Errorf("relay response exceeds max_response_body_bytes (%d)", c.maxRespBody)
	}

	var wr wireResp
	if err := json.Unmarshal(raw, &wr); err != nil {
		return nil, fmt.Errorf("relay JSON decode: %w (head=%q)", err, head(raw, 200))
	}
	if wr.Error != "" {
		return nil, fmt.Errorf("relay error: %s", wr.Error)
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(wr.B)
	if err != nil {
		return nil, fmt.Errorf("relay body decode: %w", err)
	}
	return &Response{
		Status:  wr.Status,
		Headers: wr.Headers,
		Body:    bodyBytes,
	}, nil
}

func (c *Client) pickScriptID() string {
	n := atomic.AddUint64(&c.rrCounter, 1)
	return c.scriptIDs[(n-1)%uint64(len(c.scriptIDs))]
}

func head(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
