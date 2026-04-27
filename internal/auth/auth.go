// Package auth gates the local listeners. The upstream Python project
// exposed both HTTP CONNECT and SOCKS5 with no authentication; with
// LAN sharing on, anyone routable to the host can pivot through it.
//
// We implement RFC 7235 Proxy-Authorization: Basic for HTTP, and
// RFC 1929 username/password for SOCKS5. Both use constant-time
// compare (crypto/subtle) and reject before any further parsing of
// the request.
package auth

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Gate validates credentials with constant-time compare.
//
// Rather than comparing raw user/pass strings (whose lengths are
// themselves a side-channel, since strings.EqualFold short-circuits),
// we compare SHA-256 digests. This costs ~µs but flattens the
// timing envelope to a single fixed-cost compare.
type Gate struct {
	enabled bool
	userH   [32]byte
	passH   [32]byte
}

func New(user, pass string) *Gate {
	g := &Gate{enabled: user != "" && pass != ""}
	if g.enabled {
		g.userH = sha256.Sum256([]byte(user))
		g.passH = sha256.Sum256([]byte(pass))
	}
	return g
}

// Enabled reports whether the gate will challenge.
func (g *Gate) Enabled() bool { return g.enabled }

// CheckBasic accepts the value of the Proxy-Authorization header
// (or its absence). Returns nil iff the credentials match.
func (g *Gate) CheckBasic(headerValue string) error {
	if !g.enabled {
		return nil
	}
	const prefix = "Basic "
	if len(headerValue) <= len(prefix) ||
		!strings.EqualFold(headerValue[:len(prefix)], prefix) {
		return ErrAuthRequired
	}
	raw, err := base64.StdEncoding.DecodeString(headerValue[len(prefix):])
	if err != nil {
		return ErrAuthRequired
	}
	colon := -1
	for i, b := range raw {
		if b == ':' {
			colon = i
			break
		}
	}
	if colon < 0 {
		return ErrAuthRequired
	}
	user, pass := raw[:colon], raw[colon+1:]
	uh := sha256.Sum256(user)
	ph := sha256.Sum256(pass)
	// Two ConstantTimeCompare calls so a wrong username doesn't shortcut
	// the password check.
	uOK := subtle.ConstantTimeCompare(uh[:], g.userH[:])
	pOK := subtle.ConstantTimeCompare(ph[:], g.passH[:])
	if uOK&pOK != 1 {
		return ErrAuthRequired
	}
	return nil
}

// CheckSOCKS5UserPass reads an RFC 1929 sub-negotiation from r,
// validates the credentials, and writes the response on w.
//
// Wire format on the wire (client → server):
//   VER=0x01 | ULEN | UNAME | PLEN | PASSWD
// Response (server → client):
//   VER=0x01 | STATUS  (0x00 = ok, anything else = fail)
//
// Even when auth is disabled we still consume zero bytes and return
// nil — the caller has already negotiated method 0x00 (no auth) in
// that case, so this function is not invoked.
func (g *Gate) CheckSOCKS5UserPass(r *bufio.Reader, w io.Writer) error {
	if !g.enabled {
		return errors.New("CheckSOCKS5UserPass called with auth disabled")
	}
	hdr, err := readN(r, 2)
	if err != nil {
		return err
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("socks5 auth: bad sub-negotiation version %d", hdr[0])
	}
	uname, err := readN(r, int(hdr[1]))
	if err != nil {
		return err
	}
	plenB, err := readN(r, 1)
	if err != nil {
		return err
	}
	passwd, err := readN(r, int(plenB[0]))
	if err != nil {
		return err
	}
	uh := sha256.Sum256(uname)
	ph := sha256.Sum256(passwd)
	uOK := subtle.ConstantTimeCompare(uh[:], g.userH[:])
	pOK := subtle.ConstantTimeCompare(ph[:], g.passH[:])
	if uOK&pOK != 1 {
		_, _ = w.Write([]byte{0x01, 0x01}) // STATUS != 0 → reject
		return ErrAuthRequired
	}
	_, _ = w.Write([]byte{0x01, 0x00})
	return nil
}

func readN(r *bufio.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ErrAuthRequired is returned when credentials are missing or wrong.
// Callers map it to 407 Proxy Authentication Required for HTTP, or
// to a SOCKS5 auth failure status.
var ErrAuthRequired = errors.New("proxy authentication required")

// HTTP407 is the canonical 407 response. realm is included verbatim;
// callers should ensure it does not contain quote characters.
func HTTP407(realm string) []byte {
	if realm == "" {
		realm = "relayvpn"
	}
	return []byte(
		"HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"" + realm + "\"\r\n" +
			"Connection: close\r\n" +
			"Content-Length: 0\r\n\r\n",
	)
}
