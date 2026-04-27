# GoMasterHttpRelayVPN — Go refactor

A Go rewrite of the core paths in [GoMasterHttpRelayVPN](https://github.com/SobhanYasami/GoMasterHttpRelayVPN).
Domain-fronted HTTP/SOCKS5 proxy that tunnels through a Google Apps Script relay.

This refactor focuses on the **security-critical paths**: relay envelope
auth, MITM CA, local listener auth, config validation. Several auxiliary
features from the upstream Python version are explicitly **not** ported
yet — see [Not yet ported](#not-yet-ported).

## Why a rewrite

- Reduce attack surface (single static binary, no Python dep tree).
- Fix protocol-level holes that can't be patched without breaking the
  on-the-wire format (replay, no nonce, no skew window).
- Replace ad-hoc dict access with a strict, schema-validated config.

## Layout

```
cmd/relayvpn/         main()
internal/config/      strict JSON schema, defaults, invariants
internal/auth/        Proxy-Auth (RFC 7235) + SOCKS5 user/pass (RFC 1929)
internal/mitm/        ECDSA P-256 root + leaf minting
internal/relay/       envelope (HMAC + ts + nonce), client transport, replay cache
internal/proxy/       HTTP CONNECT + SOCKS5 listeners, MITM dispatch
apps_script/Code.gs   the relay end (Apps Script side, hardened to match)
```

## Security changes vs upstream

| Area | Upstream Python | This refactor |
|---|---|---|
| Relay auth | `req.k !== AUTH_KEY` (V8 short-circuit compare, replayable forever) | HMAC-SHA256 over canonical envelope; ±60s skew window; 5-min nonce dedup cache; constant-time compare both ends |
| Local listener auth | None — `lan_sharing: true` exposes both HTTP and SOCKS5 with no creds | Optional Proxy-Auth Basic + RFC 1929 user/pass; **mandatory** when `lan_sharing` is true |
| MITM key | RSA-2048, leaves written to `/tmp` and never cleaned | ECDSA P-256, leaves in-memory only, wildcard-collapsed cache; `NotBefore` backdated 1h |
| `verify_ssl` for fronted leg | User-toggleable | Removed; always true |
| Config | `dict.get()` + silent defaults | `json.Decoder.DisallowUnknownFields()` + `Validate()` returning the first violation |
| Source IP DoS | No cap | Per-source-IP concurrency cap (default 64) |
| Block list bypass | IP-literal `CONNECT` skipped the host check | Block list applied to both name and IP forms |
| SSRF in relay | Anything UrlFetchApp can reach | Apps Script-side blocklist for `metadata.google.internal`, RFC 1918, loopback, link-local, multicast |
| Logging | URLs logged at INFO including query strings | Default level info logs path-less host only; full URL at debug |

## Threat model

In scope:

1. Off-path passive attacker on the user's local network or upstream ISP.
2. Anyone who somehow gets one valid envelope (e.g. transient log leak) —
   should **not** gain ongoing relay access.
3. Anyone on the same LAN as a `lan_sharing: true` deployment — should
   need credentials before using the proxy.

Out of scope:

1. Active TLS MITM between the proxy host and `216.239.x.x`. The fronted
   TLS leg validates against `front_domain`'s real cert chain; this is
   the upstream model and unchanged.
2. Compromise of Google. If Google logs every relay request, it logs
   them. The point of the project is censorship circumvention, not
   privacy from Google.
3. Compromise of the user's host. If the attacker has read access to
   `config.json` or `ca/ca.key`, the game is over and no design choice
   here helps.

## Setup

```bash
# 1. Build
make build

# 2. Generate a strong shared secret
openssl rand -base64 32

# 3. Copy config and fill in script_id + auth_key
cp config.example.json config.json
$EDITOR config.json

# 4. Deploy apps_script/Code.gs to https://script.google.com,
#    pasting the same auth_key into SHARED_SECRET. Deploy → New
#    deployment → Web app → Execute as: Me → Who has access: Anyone.
#    Copy the deployment ID into config.json.

# 5. Run
./relayvpn -c config.json
# First run mints ./ca/ca.crt — install it in your browser/OS
# trust store. Compare the printed SHA-256 fingerprint against
# the cert store entry to confirm.
```

For LAN sharing, set `lan_sharing: true` AND `proxy_user`/`proxy_pass`
in `config.json`. The validator refuses `lan_sharing` without auth.

## Not yet ported

These are real features in the upstream Python project I did not port.
They're tractable on top of this skeleton:

- **HTTP/2 multiplexing to the Apps Script relay.** `net/http`'s
  `Transport` will negotiate h2 automatically when the server offers
  it (it does), so this is mostly an idle-conn-pool tuning question
  rather than new code. Verify with `GODEBUG=http2debug=1`.
- **Range-parallel chunked downloads.** Significant — the upstream
  splits large GETs into N parallel range requests across multiple
  Apps Script deployments. Belongs in `internal/relay/` as a
  `ChunkedClient` that wraps `Client.Do` and reassembles.
- **Brotli / Zstd content-encoding decode.** `net/http` only decodes
  gzip transparently. Add `andybalholm/brotli` and
  `klauspost/compress/zstd` and wire them into a response decoder
  in the proxy.
- **Direct (non-MITM) tunneling for whitelisted Google domains.** The
  upstream code has an SNI-rewrite fast path that bypasses MITM for
  trusted Google traffic; everything else goes through Apps Script.
  This refactor relays everything through Apps Script.
- **Cross-platform CA installer.** `cert_installer.py` invokes
  `update-ca-certificates` / `security add-trusted-cert` /
  `certutil` / Firefox NSS. Worth a separate package.
- **IP scanner** (`google_ip_scanner.py`).
- **Response cache.** Removed because the upstream version is
  cache-poisoning-prone under `lan_sharing`. If reintroduced, key
  must include the source IP and the request must be uncredentialed.

## Tests

```bash
go test -race -count=1 ./...
```

Coverage focuses on the protocol invariants (envelope round-trip,
tamper detection, skew window, nonce dedup) and the config invariants
(strict decode, port collision, LAN-without-auth rejection). MITM
mint tests verify the leaf chains to the CA and that concurrent mints
of the same host coalesce.

## License

MIT (same as upstream).
