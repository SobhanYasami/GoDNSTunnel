package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/SobhanYasami/GoMasterHttpRelayVPN/internal/mitm"
)

// handleSOCKS5 implements RFC 1928 with optional RFC 1929 user/pass.
//
// Supported methods (offered in the auth-method handshake):
//   0x00 NO AUTHENTICATION         (when s.Auth.Enabled() is false)
//   0x02 USERNAME/PASSWORD         (when s.Auth.Enabled() is true)
//
// Supported commands:
//   0x01 CONNECT                   (the only sane choice for a relay)
//
// BIND and UDP ASSOCIATE are explicitly rejected.
//
// Address types:
//   0x01 IPv4
//   0x03 DOMAINNAME
//   0x04 IPv6
//
// Behaviour: after CONNECT succeeds, the SOCKS5 client expects to
// speak directly to the target. Since we relay through Apps Script,
// we instead synthesize a TLS server endpoint (using our MITM cert
// for the CONNECT target's hostname) and let the client speak HTTPS
// to it. Each HTTP request inside the TLS tunnel is then relayed.
//
// SOCKS5 with raw IP-only targets (no SNI on the wire) is degraded:
// we have no hostname to mint a leaf for, so we reject. This is
// the correct call rather than minting a cert for the IP — Telegram
// MTProto over SOCKS5 fails the same way in the upstream Python
// project, and the README acknowledges it. Use HTTP proxy for those.
func (s *Server) handleSOCKS5(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(s.IdleTimeout))
	br := bufio.NewReader(c)

	// === Method negotiation ===
	hdr, err := readN(br, 2)
	if err != nil || hdr[0] != 0x05 {
		return
	}
	methods, err := readN(br, int(hdr[1]))
	if err != nil {
		return
	}
	pickedMethod := byte(0xff)
	if s.Auth.Enabled() {
		if containsByte(methods, 0x02) {
			pickedMethod = 0x02
		}
	} else {
		if containsByte(methods, 0x00) {
			pickedMethod = 0x00
		}
	}
	if _, err := c.Write([]byte{0x05, pickedMethod}); err != nil {
		return
	}
	if pickedMethod == 0xff {
		return
	}
	if pickedMethod == 0x02 {
		if err := s.Auth.CheckSOCKS5UserPass(br, c); err != nil {
			return
		}
	}

	// === Request ===
	req, err := readN(br, 4)
	if err != nil || req[0] != 0x05 {
		return
	}
	if req[1] != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}
	atyp := req[3]

	var targetHost string
	switch atyp {
	case 0x01: // IPv4
		ip, err := readN(br, 4)
		if err != nil {
			return
		}
		// Reject IP-only — see comment above.
		_ = ip
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		return
	case 0x03: // DOMAINNAME
		ln, err := readN(br, 1)
		if err != nil {
			return
		}
		host, err := readN(br, int(ln[0]))
		if err != nil {
			return
		}
		targetHost = string(host)
	case 0x04: // IPv6
		ip, err := readN(br, 16)
		if err != nil {
			return
		}
		_ = ip
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	portB, err := readN(br, 2)
	if err != nil {
		return
	}
	targetPort := strconv.Itoa(int(binary.BigEndian.Uint16(portB)))

	if s.isBlocked(targetHost) {
		_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // not allowed by ruleset
		return
	}

	// SUCCESS reply with bound addr 0.0.0.0:0 (we don't actually bind anywhere).
	_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	_ = c.SetDeadline(time.Time{})

	// Now run the same MITM TLS loop as CONNECT.
	ctx := context.WithValue(context.Background(), mitm.ConnectHostKey, targetHost)
	tlsCfg := s.Mint.TLSConfig()
	tlsConn := tls.Server(prebufferedConn{Conn: c, r: br}, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.Logger.Debug("socks5 mitm handshake", "host", targetHost, "err", err)
		return
	}
	defer tlsConn.Close()

	innerBR := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetDeadline(time.Now().Add(s.IdleTimeout))
		req, err := http.ReadRequest(innerBR)
		if err != nil {
			return
		}
		if err := s.relayHTTPS(tlsConn, req, targetHost, targetPort); err != nil {
			return
		}
		if !shouldKeepAlive(req) {
			return
		}
	}
}

// containsByte reports whether b contains v.
func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// readN reads exactly n bytes from r.
func readN(r *bufio.Reader, n int) ([]byte, error) {
	out := make([]byte, n)
	_, err := io.ReadFull(r, out)
	return out, err
}
