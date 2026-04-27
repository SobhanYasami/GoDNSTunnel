package mitm

import (
	"crypto/x509"
	"sync"
	"testing"
)

func mustCA(t *testing.T) *CA {
	t.Helper()
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestMintLeafChainsToCA(t *testing.T) {
	ca := mustCA(t)
	mint := NewMint(ca)

	cert, err := mint.Get("foo.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leafX, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leafX.Verify(x509.VerifyOptions{
		Roots:   pool,
		DNSName: "foo.example.com",
	}); err != nil {
		t.Fatalf("leaf verify: %v", err)
	}
}

func TestWildcardCollapse(t *testing.T) {
	ca := mustCA(t)
	mint := NewMint(ca)

	c1, err := mint.Get("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := mint.Get("b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Same canonical key → same DER cert (object identity OK because
	// assemble() pulls from the same minted struct).
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Fatal("expected wildcard collapse: a/b.example.com share leaf")
	}
}

func TestConcurrentMintCoalesces(t *testing.T) {
	ca := mustCA(t)
	mint := NewMint(ca)

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([][]byte, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			c, err := mint.Get("concur.example.com")
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = c.Certificate[0]
		}()
	}
	wg.Wait()
	for i := 1; i < goroutines; i++ {
		if string(results[i]) != string(results[0]) {
			t.Fatalf("goroutine %d got distinct cert — coalesce failed", i)
		}
	}
}
