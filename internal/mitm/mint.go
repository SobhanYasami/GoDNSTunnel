package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// canonKey collapses subdomains under their wildcard parent so we
// don't mint a separate leaf for every blog post on a CDN.
//
// Examples:
//   foo.example.com   → "*.example.com"
//   example.com       → "example.com"
//   192.0.2.1         → "192.0.2.1"
//   www.co.uk         → "*.co.uk"  (acceptable: this leaf is never
//                                   trusted publicly, only by the user)
//
// We deliberately do NOT consult a public-suffix list. The leaf is
// signed by a CA that only the local user trusts; a "wildcard for
// .co.uk" leaf served back to that same user is not a security
// problem — it just means the wildcard collapse is coarser than
// it could be. Adding PSL is a worthwhile follow-up.
func canonKey(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return "*." + strings.Join(parts[1:], ".")
}

// Get returns a *tls.Certificate suitable for serving SNI=host.
// Safe for concurrent use; identical-key mints coalesce.
func (m *Mint) Get(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, errors.New("mint: empty host")
	}
	key := canonKey(host)

	m.mu.Lock()
	if cached, ok := m.cache[key]; ok {
		m.mu.Unlock()
		return assemble(cached, m.ca), nil
	}
	if wg, ok := m.inflt[key]; ok {
		m.mu.Unlock()
		wg.Wait()
		m.mu.Lock()
		cached, ok := m.cache[key]
		m.mu.Unlock()
		if !ok {
			return nil, errors.New("mint: in-flight mint failed")
		}
		return assemble(cached, m.ca), nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	m.inflt[key] = wg
	m.mu.Unlock()

	leaf, err := m.mintLocked(key)

	m.mu.Lock()
	delete(m.inflt, key)
	if err == nil {
		m.cache[key] = leaf
		m.leaves++
	}
	m.mu.Unlock()
	wg.Done()

	if err != nil {
		return nil, err
	}
	return assemble(leaf, m.ca), nil
}

func (m *Mint) mintLocked(key string) (*minted, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cn := key
	if len(cn) > 63 { // X.509 CN limit
		cn = cn[:63]
	}
	now := time.Now().UTC().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Must be valid leaf, NOT a CA.
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip := net.ParseIP(strings.Trim(key, "[]")); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		// Both apex and wildcard if applicable.
		tmpl.DNSNames = []string{key}
		if strings.HasPrefix(key, "*.") {
			tmpl.DNSNames = append(tmpl.DNSNames, key[2:])
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca.Cert, &priv.PublicKey, m.ca.key)
	if err != nil {
		return nil, err
	}
	return &minted{cert: der, keyPair: tlsKeyPair{priv: priv}}, nil
}

func assemble(m *minted, ca *CA) *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{m.cert, ca.CertDER},
		PrivateKey:  m.keyPair.priv,
	}
}

// TLSConfig returns a tls.Config whose GetCertificate is wired to m.
// ALPN is fixed to http/1.1 — we don't speak h2 to the browser yet,
// because the proxy upstream relay multiplexes request/response as
// JSON envelopes which don't compose cleanly with h2 streams from
// the client.
func (m *Mint) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hi.ServerName
			if host == "" {
				// Fallback: the CONNECT target hostname, attached by
				// the listener via context if SNI was missing.
				if v, ok := hi.Context().Value(connectHostKey{}).(string); ok {
					host = v
				}
			}
			return m.Get(host)
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
}

// connectHostKey is exported via the proxy package so the listener
// can stash the CONNECT host on the context before the TLS handshake.
type connectHostKey struct{}

// ConnectHostKey is the context key used by the proxy listener.
var ConnectHostKey = connectHostKey{}
