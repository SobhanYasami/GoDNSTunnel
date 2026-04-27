// Package proxy implements the local HTTP and SOCKS5 listeners that
// front the relay. The CONNECT path runs MITM TLS interception, then
// pumps each request/response through the Apps Script relay.
//
// What this implements vs the Python upstream:
//
//   - Auth gate (Proxy-Authorization for HTTP, RFC 1929 for SOCKS5)
//     enforced before any URL parse.
//   - Per-source-IP concurrency cap to bound DoS via connection
//     storms. Default 64, override via Server.MaxConnsPerSrc.
//   - Block-list applied to BOTH hostname and IP-literal CONNECTs
//     (the upstream code only blocked hostname CONNECTs, so a
//     client could bypass via direct IP).
//
// What's NOT implemented yet (TODO, marked clearly):
//
//   - Direct (non-MITM) CONNECT tunneling through Google's SNI-
//     rewrite path. We always relay through Apps Script.
//   - Range-parallel chunked downloads.
//   - Brotli / zstd content-encoding decode (gzip + deflate only).
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/auth"
	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/mitm"
	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/relay"
)

// Server is the local HTTP+SOCKS5 listener.
type Server struct {
	Addr            string        // e.g. "127.0.0.1:8085"
	SOCKS5Addr      string        // e.g. "127.0.0.1:1080" or "" to disable
	Auth            *auth.Gate    // nil = open (only safe on loopback)
	Mint            *mitm.Mint    // for CONNECT MITM
	Relay           *relay.Client // for outbound requests
	BlockHosts      []string      // exact + ".suffix" entries
	BypassHosts     []string      // direct (no-MITM, no-relay) — TODO
	MaxConnsPerSrc  int           // 0 → 64
	IdleTimeout     time.Duration // 0 → 60s
	Logger          *slog.Logger

	conns    sync.Map // src IP → *int32 inflight count
	listener net.Listener
	socks    net.Listener
	wg       sync.WaitGroup
	quit     atomic.Bool
}

// Run blocks until ctx is cancelled or a fatal listen error occurs.
func (s *Server) Run(ctx context.Context) error {
	if s.MaxConnsPerSrc == 0 {
		s.MaxConnsPerSrc = 64
	}
	if s.IdleTimeout == 0 {
		s.IdleTimeout = 60 * time.Second
	}
	if s.Logger == nil {
		s.Logger = slog.Default()
	}

	httpL, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Addr, err)
	}
	s.listener = httpL
	s.Logger.Info("HTTP proxy listening", "addr", s.Addr, "auth", s.Auth.Enabled())

	if s.SOCKS5Addr != "" {
		l, err := net.Listen("tcp", s.SOCKS5Addr)
		if err != nil {
			httpL.Close()
			return fmt.Errorf("listen socks5 %s: %w", s.SOCKS5Addr, err)
		}
		s.socks = l
		s.Logger.Info("SOCKS5 proxy listening", "addr", s.SOCKS5Addr, "auth", s.Auth.Enabled())
	}

	go func() {
		<-ctx.Done()
		s.quit.Store(true)
		_ = httpL.Close()
		if s.socks != nil {
			_ = s.socks.Close()
		}
	}()

	go s.acceptLoop(httpL, s.handleHTTP)
	if s.socks != nil {
		go s.acceptLoop(s.socks, s.handleSOCKS5)
	}

	<-ctx.Done()
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop(l net.Listener, handler func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			if s.quit.Load() {
				return
			}
			s.Logger.Warn("accept", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.acquireSlot(c) {
			s.Logger.Warn("conn-cap exceeded", "src", c.RemoteAddr())
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.releaseSlot(c)
			defer c.Close()
			handler(c)
		}()
	}
}

func (s *Server) acquireSlot(c net.Conn) bool {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return false
	}
	v, _ := s.conns.LoadOrStore(host, new(int32))
	cnt := v.(*int32)
	for {
		cur := atomic.LoadInt32(cnt)
		if int(cur) >= s.MaxConnsPerSrc {
			return false
		}
		if atomic.CompareAndSwapInt32(cnt, cur, cur+1) {
			return true
		}
	}
}

func (s *Server) releaseSlot(c net.Conn) {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	if v, ok := s.conns.Load(host); ok {
		atomic.AddInt32(v.(*int32), -1)
	}
}

// handleHTTP reads the first request line + headers and routes:
//   - CONNECT host:port  → auth → MITM tunnel → relay
//   - {GET,POST,...} URL → auth → relay direct (legacy http://)
//
// We deliberately do NOT accept abs-path requests (origin-form) —
// HTTP proxies receive absolute-form requests per RFC 9112 §3.2.2.
// An origin-form request is most likely a misconfigured client and
// telling them so loudly is more useful than guessing.
func (s *Server) handleHTTP(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(s.IdleTimeout))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if s.Auth.Enabled() {
		hv := req.Header.Get("Proxy-Authorization")
		if err := s.Auth.CheckBasic(hv); err != nil {
			c.Write(auth.HTTP407("relayvpn"))
			return
		}
		// Don't forward the credential to the origin.
		req.Header.Del("Proxy-Authorization")
	}

	if req.Method == http.MethodConnect {
		s.doConnect(c, br, req)
		return
	}
	s.doAbsoluteHTTP(c, req)
}

// doConnect: client has issued `CONNECT host:port HTTP/1.1`.
// We verify the policy, send 200, then MITM the TLS handshake and
// loop reading requests off the inner TLS conn, relaying each.
func (s *Server) doConnect(c net.Conn, br *bufio.Reader, req *http.Request) {
	host, port, err := net.SplitHostPort(req.RequestURI)
	if err != nil {
		host = req.RequestURI
		port = "443"
	}
	if s.isBlocked(host) {
		c.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	// Acknowledge the CONNECT.
	if _, err := c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{}) // disarm idle timeout — the handshake is immediate

	// Stash the CONNECT host so SNI fallbacks work.
	ctx := context.WithValue(context.Background(), mitm.ConnectHostKey, host)

	tlsCfg := s.Mint.TLSConfig()
	tlsConn := tls.Server(prebufferedConn{Conn: c, r: br}, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.Logger.Debug("mitm handshake", "host", host, "err", err)
		return
	}
	defer tlsConn.Close()

	innerBR := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetDeadline(time.Now().Add(s.IdleTimeout))
		ireq, err := http.ReadRequest(innerBR)
		if err != nil {
			return
		}
		// Keep-alive loop: each iteration handles one request.
		if err := s.relayHTTPS(tlsConn, ireq, host, port); err != nil {
			s.Logger.Debug("relay", "host", host, "err", err)
			return
		}
		if !shouldKeepAlive(ireq) {
			return
		}
	}
}

// doAbsoluteHTTP handles GET/POST/... http://... requests received
// on the proxy. (The CONNECT path is for HTTPS; this is for plain
// http:// where some browsers still forward the absolute URL.)
func (s *Server) doAbsoluteHTTP(c net.Conn, req *http.Request) {
	if req.URL == nil || !req.URL.IsAbs() {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if s.isBlocked(req.URL.Hostname()) {
		c.Write([]byte("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	if err := s.relayPlain(c, req); err != nil {
		s.Logger.Debug("relay http", "url", req.URL.String(), "err", err)
	}
}

// relayHTTPS converts the inner request → relay.Request, dispatches,
// and writes the relay response back to the TLS conn. The full URL
// is reconstructed from the CONNECT target and the inner Request-URI.
func (s *Server) relayHTTPS(tlsConn *tls.Conn, req *http.Request, host, port string) error {
	body, err := io.ReadAll(io.LimitReader(req.Body, 16<<20))
	if err != nil {
		return err
	}
	url := "https://" + host
	if port != "" && port != "443" {
		url += ":" + port
	}
	url += req.URL.RequestURI()

	rr := relay.Request{
		Method:      req.Method,
		URL:         url,
		Headers:     pickHeaders(req.Header),
		Body:        body,
		ContentType: req.Header.Get("Content-Type"),
		Redirect:    false, // let the browser handle 3xx
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := s.Relay.Do(ctx, rr)
	if err != nil {
		writeBadGateway(tlsConn, err)
		return err
	}
	return writeRelayResponse(tlsConn, resp)
}

func (s *Server) relayPlain(c net.Conn, req *http.Request) error {
	body, err := io.ReadAll(io.LimitReader(req.Body, 16<<20))
	if err != nil {
		return err
	}
	rr := relay.Request{
		Method:      req.Method,
		URL:         req.URL.String(),
		Headers:     pickHeaders(req.Header),
		Body:        body,
		ContentType: req.Header.Get("Content-Type"),
		Redirect:    false,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := s.Relay.Do(ctx, rr)
	if err != nil {
		writeBadGateway(c, err)
		return err
	}
	return writeRelayResponse(c, resp)
}

// pickHeaders strips hop-by-hop headers (RFC 9110 §7.6.1) and
// proxy-credential headers before forwarding.
func pickHeaders(h http.Header) map[string]string {
	skip := map[string]struct{}{
		"connection":          {},
		"proxy-connection":    {},
		"keep-alive":          {},
		"transfer-encoding":   {},
		"te":                  {},
		"trailer":             {},
		"upgrade":             {},
		"proxy-authorization": {},
		"proxy-authenticate":  {},
		// Apps Script will set these:
		"host":           {},
		"content-length": {},
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		lk := strings.ToLower(k)
		if _, drop := skip[lk]; drop {
			continue
		}
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func (s *Server) isBlocked(hostOrIP string) bool {
	host := strings.ToLower(strings.TrimSuffix(hostOrIP, "."))
	for _, entry := range s.BlockHosts {
		entry = strings.ToLower(entry)
		if strings.HasPrefix(entry, ".") {
			if strings.HasSuffix(host, entry) || host == entry[1:] {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

// shouldKeepAlive: HTTP/1.1 default is keep-alive; HTTP/1.0 default
// is close. Connection: close on either overrides.
func shouldKeepAlive(req *http.Request) bool {
	conn := strings.ToLower(req.Header.Get("Connection"))
	if strings.Contains(conn, "close") {
		return false
	}
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return strings.Contains(conn, "keep-alive")
	}
	return true
}

func writeRelayResponse(w io.Writer, r *relay.Response) error {
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", r.Status, http.StatusText(r.Status))
	dropHopByHop := func(name string) bool {
		switch strings.ToLower(name) {
		case "connection", "proxy-connection", "keep-alive",
			"transfer-encoding", "te", "trailer", "upgrade":
			return true
		}
		return false
	}
	hadCL := false
	for k, v := range r.Headers {
		if dropHopByHop(k) {
			continue
		}
		if strings.EqualFold(k, "content-length") {
			hadCL = true
		}
		switch vv := v.(type) {
		case string:
			fmt.Fprintf(&sb, "%s: %s\r\n", k, sanitizeHeader(vv))
		case []any:
			for _, item := range vv {
				if s, ok := item.(string); ok {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, sanitizeHeader(s))
				}
			}
		}
	}
	if !hadCL {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(r.Body))
	}
	sb.WriteString("\r\n")

	if _, err := io.WriteString(w, sb.String()); err != nil {
		return err
	}
	_, err := w.Write(r.Body)
	return err
}

// sanitizeHeader strips CR/LF — defends against header injection if
// the upstream relay ever forwards a tainted header value.
func sanitizeHeader(v string) string {
	if !strings.ContainsAny(v, "\r\n") {
		return v
	}
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if v[i] != '\r' && v[i] != '\n' {
			out = append(out, v[i])
		}
	}
	return string(out)
}

func writeBadGateway(w io.Writer, err error) {
	msg := "relay error"
	if err != nil {
		msg = err.Error()
	}
	body := []byte(msg)
	fmt.Fprintf(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n", len(body))
	w.Write(body)
}

// prebufferedConn lets the TLS server consume the bytes that bufio
// already pulled off the underlying conn during request parsing.
type prebufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p prebufferedConn) Read(b []byte) (int, error) {
	if p.r != nil && p.r.Buffered() > 0 {
		return p.r.Read(b)
	}
	return p.Conn.Read(b)
}

// Compile-time guards that the proxy types match the contracts.
var (
	_ io.Reader    = (*prebufferedConn)(nil)
	_ io.Writer    = (*prebufferedConn)(nil)
	_ net.Conn     = (*prebufferedConn)(nil)
	_ http.Handler = (*nopHandler)(nil) // kept for future use
	_              = errors.New
)

type nopHandler struct{}

func (nopHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}
