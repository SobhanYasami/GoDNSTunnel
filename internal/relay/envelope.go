// Package relay speaks to the Apps Script endpoint.
//
// The upstream protocol authenticates by sending the shared secret
// inside the JSON body and comparing with `!==`. That is replayable
// (no timestamp/nonce) and timing-leaky (V8 string compare short-
// circuits on first differing byte). This package replaces it with:
//
//   v   = 1                 protocol version (so we can rev later)
//   ts  = unix milliseconds  ±60s skew window enforced server-side
//   n   = base64(16 random)  per-request nonce, replay-cached 5min
//   m,u,h,b,ct,r             same fields as before
//   s   = HMAC-SHA256(K, canonical(envelope))
//
// The canonical signing string is a fixed pipe-separated form so we
// don't depend on JSON serializer key ordering between Go and Apps
// Script. The body and headers are SHA-256'd before being included
// in the signing string to keep it bounded.
package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const (
	ProtoVersion = 1

	// MaxClockSkew is the half-window. A request whose ts is more
	// than MaxClockSkew off the server's clock is rejected. Apps
	// Script servers track wall-clock pretty accurately, but client
	// machines (laptops, phones with off batteries) can drift; 60s
	// is a balance between replay window and usability.
	MaxClockSkew = 60 * time.Second

	// NonceTTL is how long the server-side anti-replay cache keeps
	// each nonce. Must be ≥ 2 * MaxClockSkew or replay is possible
	// at the edges.
	NonceTTL = 5 * time.Minute
)

// Request is the application-level fields of a relay call.
// Body is bytes, but is base64-encoded on the wire (req.b).
type Request struct {
	Method      string            // GET, POST, ...
	URL         string            // absolute URL on the origin
	Headers     map[string]string // origin headers
	Body        []byte            // origin body (raw)
	ContentType string
	Redirect    bool // follow redirects on the relay
}

// Envelope is the on-the-wire JSON object POSTed to Apps Script.
type Envelope struct {
	V   int               `json:"v"`
	TS  int64             `json:"ts"`
	N   string            `json:"n"`
	M   string            `json:"m"`
	U   string            `json:"u"`
	H   map[string]string `json:"h,omitempty"`
	B   string            `json:"b,omitempty"`  // base64
	CT  string            `json:"ct,omitempty"`
	R   bool              `json:"r"`
	Sig string            `json:"s"`
}

// Build constructs and signs an envelope for r using key.
//
// Caller must keep `key` outside the envelope. Anyone with `key` who
// captures one envelope gains nothing they couldn't already produce.
func Build(key []byte, r Request) (*Envelope, error) {
	if len(key) == 0 {
		return nil, errors.New("relay: empty signing key")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	env := &Envelope{
		V:  ProtoVersion,
		TS: time.Now().UnixMilli(),
		N:  base64.StdEncoding.EncodeToString(nonce[:]),
		M:  r.Method,
		U:  r.URL,
		H:  r.Headers,
		CT: r.ContentType,
		R:  r.Redirect,
	}
	if len(r.Body) > 0 {
		env.B = base64.StdEncoding.EncodeToString(r.Body)
	}
	env.Sig = sign(key, env)
	return env, nil
}

// Marshal returns the envelope as the JSON bytes you POST.
func (e *Envelope) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// Verify recomputes the HMAC and the freshness checks. The replay
// check (nonce uniqueness) is left to the caller — see VerifyServer.
func Verify(key []byte, e *Envelope) error {
	if e.V != ProtoVersion {
		return fmt.Errorf("relay: bad version %d", e.V)
	}
	now := time.Now().UnixMilli()
	if abs64(now-e.TS) > MaxClockSkew.Milliseconds() {
		return errors.New("relay: timestamp out of skew window")
	}
	if !validNonce(e.N) {
		return errors.New("relay: bad nonce")
	}
	want := sign(key, e)
	got, err := hex.DecodeString(e.Sig)
	if err != nil {
		return errors.New("relay: bad signature encoding")
	}
	wantB, _ := hex.DecodeString(want)
	if !hmac.Equal(wantB, got) {
		return errors.New("relay: signature mismatch")
	}
	return nil
}

// canonical builds the signing string. Format:
//
//   v\n ts\n n\n m\n u\n ct\n r(0|1)\n bHash\n hHash
//
// where bHash = hex(sha256(body bytes)), hHash = hex(sha256(canonical
// headers JSON: keys lowercased, sorted, separator-strict)).
//
// "\n" is a forbidden character in single-line headers per RFC 9110
// §5.5, and we reject any \n in M/U/CT before signing. So no field
// can smuggle a newline that confuses the canonicalization (length-
// extension by ambiguity).
func canonical(e *Envelope) []byte {
	bHash := sha256.Sum256(decodeB64Body(e.B))
	hHash := sha256.Sum256(canonicalHeaders(e.H))

	var sb []byte
	sb = strconv.AppendInt(sb, int64(e.V), 10)
	sb = append(sb, '\n')
	sb = strconv.AppendInt(sb, e.TS, 10)
	sb = append(sb, '\n')
	sb = append(sb, e.N...)
	sb = append(sb, '\n')
	sb = append(sb, sanitize(e.M)...)
	sb = append(sb, '\n')
	sb = append(sb, sanitize(e.U)...)
	sb = append(sb, '\n')
	sb = append(sb, sanitize(e.CT)...)
	sb = append(sb, '\n')
	if e.R {
		sb = append(sb, '1')
	} else {
		sb = append(sb, '0')
	}
	sb = append(sb, '\n')
	sb = append(sb, hex.EncodeToString(bHash[:])...)
	sb = append(sb, '\n')
	sb = append(sb, hex.EncodeToString(hHash[:])...)
	return sb
}

func sign(key []byte, e *Envelope) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical(e))
	return hex.EncodeToString(mac.Sum(nil))
}

func sanitize(s string) string {
	// Reject embedded \n / \r so they can't cross canonical fields.
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return ""
		}
	}
	return s
}

func canonicalHeaders(h map[string]string) []byte {
	if len(h) == 0 {
		return []byte("{}")
	}
	keys := make([]string, 0, len(h))
	lowered := make(map[string]string, len(h))
	for k, v := range h {
		lk := lowerASCII(k)
		lowered[lk] = v
		keys = append(keys, lk)
	}
	sort.Strings(keys)
	// Hand-rolled JSON to avoid encoder map-iteration nondeterminism.
	var b []byte
	b = append(b, '{')
	for i, k := range keys {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendJSONString(b, k)
		b = append(b, ':')
		b = appendJSONString(b, lowered[k])
	}
	b = append(b, '}')
	return b
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, []byte(fmt.Sprintf(`\u%04x`, c))...)
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

func decodeB64Body(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func validNonce(s string) bool {
	// 16 raw bytes → ceil(16/3)*4 = 24 b64 chars (with padding "==").
	if len(s) != 24 {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
