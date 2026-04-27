// Package mitm mints per-host TLS leaf certificates signed by a
// locally-trusted CA, so the proxy can decrypt and re-encrypt the
// browser's HTTPS traffic before forwarding it through the relay.
//
// Differences from the upstream Python implementation:
//
//   - Keys are ECDSA P-256, not RSA-2048. ~10× faster to mint and
//     equivalent strength. (RSA-2048 ≈ 112-bit security level;
//     ECDSA P-256 ≈ 128-bit security level. See NIST SP 800-57.)
//   - Leaf certs and keys live ONLY in memory. The Python code wrote
//     each leaf to /tmp; private keys leaked across runs.
//   - The leaf cache collapses subdomains under a single wildcard SAN
//     (a.example.com and b.example.com share *.example.com), so most
//     navigation only triggers one mint per eTLD+1.
//   - NotBefore is backdated by 1h to tolerate skewed client clocks.
package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// CA holds the root key + cert. Used to sign leaves; never used as
// a TLS server context itself.
type CA struct {
	Cert    *x509.Certificate
	CertDER []byte
	key     *ecdsa.PrivateKey
}

// LoadOrCreate reads CA material from dir/{ca.crt, ca.key}, creating
// it on first run. The key is written with mode 0600 on POSIX.
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if pemCert, err := os.ReadFile(certPath); err == nil {
		pemKey, kerr := os.ReadFile(keyPath)
		if kerr != nil {
			return nil, fmt.Errorf("ca cert exists but key missing: %w", kerr)
		}
		return parseCA(pemCert, pemKey)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return generateCA(certPath, keyPath)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, errors.New("ca.crt: not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca.crt: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("ca.key: not PEM")
	}
	// We always write PKCS#8 — but accept SEC1 (legacy) on read so users
	// who imported an earlier key don't get locked out.
	var key *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ca.key: not an ECDSA key")
		}
		key = ek
	} else if k, err := x509.ParseECPrivateKey(kb.Bytes); err == nil {
		key = k
	} else {
		return nil, errors.New("ca.key: unrecognized format (need PKCS#8 or SEC1 ECDSA)")
	}
	return &CA{Cert: cert, CertDER: cb.Bytes, key: key}, nil
}

func generateCA(certPath, keyPath string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "RelayVPN Local Root",
			Organization: []string{"RelayVPN (local CA)"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // sign leaves only, no intermediates
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := writeCert(certPath, der); err != nil {
		return nil, err
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertDER: der, key: key}, nil
}

func writeCert(path string, der []byte) error {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return os.WriteFile(path, pemBytes, 0o644)
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	mode := os.FileMode(0o600)
	if runtime.GOOS == "windows" {
		// Windows ignores chmod bits; rely on default ACLs of %USERPROFILE%.
		mode = 0o644
	}
	return os.WriteFile(path, pemBytes, mode)
}

// Mint generates per-host certs. Concurrency-safe; in-flight mints
// for the same key coalesce via singleflight-style locking.
type Mint struct {
	ca     *CA
	mu     sync.Mutex
	cache  map[string]*minted
	inflt  map[string]*sync.WaitGroup
	leaves int // count for diagnostics
}

type minted struct {
	cert    []byte // leaf DER
	keyPair tlsKeyPair
}

// tlsKeyPair is opaque to callers — they call (*Mint).Get and receive
// a *tls.Certificate ready to slot into a *tls.Config.GetCertificate.
type tlsKeyPair struct {
	priv *ecdsa.PrivateKey
}

func NewMint(ca *CA) *Mint {
	return &Mint{
		ca:    ca,
		cache: make(map[string]*minted, 256),
		inflt: make(map[string]*sync.WaitGroup),
	}
}
