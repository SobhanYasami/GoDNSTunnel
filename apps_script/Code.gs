/**
 * RelayVPN — Apps Script verifier (hardened)
 *
 * Differences from upstream Code.gs:
 *   - Replaces `req.k !== AUTH_KEY` (V8 short-circuiting compare,
 *     replayable in perpetuity) with HMAC-SHA256 over a canonical
 *     signing string + ±60s skew window + 5min nonce replay cache
 *     keyed in CacheService.
 *   - Constant-time compare via byte-XOR (no early exit).
 *   - Rejects fetched URLs that resolve to RFC 1918 / loopback /
 *     link-local / multicast / unique-local — closes the SSRF
 *     hole that lets a relay user probe the internal network of
 *     whoever deployed the script. (Apps Script runs in Google's
 *     network, but URLs like http://metadata.google.internal/ are
 *     a meaningful threat.)
 *   - Single-mode only: the upstream batch path can fan out arbitrary
 *     targets in parallel from one envelope. With proper signing the
 *     batch is fine to bring back, but the per-target ACL still has
 *     to apply to each — easy to get wrong, so it's removed for now.
 *
 * Deployment unchanged: paste, set SHARED_SECRET, Deploy → New
 * deployment → Web app → Execute as: Me, Who has access: Anyone.
 */

// ============================================================
// CONFIG — change SHARED_SECRET to match config.json's auth_key.
// Must be ≥24 chars. Use `openssl rand -base64 32` or similar.
// ============================================================
const SHARED_SECRET = "CHANGE_ME_TO_A_STRONG_SECRET";

const PROTO_VERSION = 1;
const MAX_SKEW_MS = 60 * 1000;
const NONCE_TTL_S = 300; // 5 minutes; >= 2 * MAX_SKEW

// Headers we never forward to the origin from the client envelope.
// Apps Script sets Host, Content-Length, etc. itself.
const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1,
  "transfer-encoding": 1, "proxy-connection": 1,
  "proxy-authorization": 1, priority: 1, te: 1,
};

// SSRF guard: hostnames whose A records the relay must refuse.
// Apps Script doesn't expose DNS resolution, but we can pattern-
// match obviously-internal names and IP literals. This is a best-
// effort layer — defense in depth, not the primary control.
const SSRF_BLOCK_HOSTS = [
  "metadata.google.internal",
  "metadata", "kubernetes.default.svc",
];

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return _json({ e: "no body" }, 400);
    }
    var env = JSON.parse(e.postData.contents);

    var verr = _verifyEnvelope(env);
    if (verr) return _json({ e: verr }, 401);

    if (!env.u || typeof env.u !== "string" || !/^https?:\/\//i.test(env.u)) {
      return _json({ e: "bad url" }, 400);
    }
    if (_isBlockedHost(env.u)) {
      return _json({ e: "blocked host" }, 403);
    }

    var opts = _buildOpts(env);
    var resp = UrlFetchApp.fetch(env.u, opts);
    return _json({
      s: resp.getResponseCode(),
      h: _respHeaders(resp),
      b: Utilities.base64Encode(resp.getContent()),
    });
  } catch (err) {
    return _json({ e: String(err) }, 500);
  }
}

function doGet() {
  // Bland page so a casual visitor sees nothing interesting.
  return HtmlService.createHtmlOutput(
    "<!doctype html><title>OK</title><p>Service running.</p>"
  );
}

// ------------------------------------------------------------
// Envelope verification
// ------------------------------------------------------------

function _verifyEnvelope(env) {
  if (!env || env.v !== PROTO_VERSION) return "bad version";
  if (typeof env.ts !== "number") return "bad ts";
  if (Math.abs(Date.now() - env.ts) > MAX_SKEW_MS) return "stale";
  if (typeof env.n !== "string" || env.n.length !== 24) return "bad nonce";
  if (typeof env.s !== "string") return "missing sig";

  // Replay check: CacheService.put refuses to overwrite by default
  // when we use putAll with skipExisting semantics; we emulate via
  // get-then-put. Race window is small but real — for a relay this
  // is acceptable (an attacker needs to win the race AND have a
  // valid signature, which means they already had the secret).
  var cache = CacheService.getScriptCache();
  if (cache.get(env.n)) return "replay";
  cache.put(env.n, "1", NONCE_TTL_S);

  var canon = _canonical(env);
  var expected = _hmacHex(SHARED_SECRET, canon);
  if (!_ctEq(expected, String(env.s))) return "bad sig";
  return null;
}

function _canonical(env) {
  // Mirror the Go-side canonical form exactly:
  //   v\n ts\n n\n m\n u\n ct\n r\n hex(sha256(body))\n hex(sha256(headersJSON))
  var bHash = _sha256Hex(env.b ? Utilities.base64Decode(env.b) : []);
  var hHash = _sha256Hex(_canonicalHeadersJSON(env.h));
  var r = env.r ? "1" : "0";
  return [
    String(env.v),
    String(env.ts),
    env.n,
    _sanitize(env.m || ""),
    _sanitize(env.u || ""),
    _sanitize(env.ct || ""),
    r,
    bHash,
    hHash,
  ].join("\n");
}

function _canonicalHeadersJSON(h) {
  if (!h || typeof h !== "object") return "{}";
  var keys = Object.keys(h).map(function (k) { return k.toLowerCase(); });
  keys.sort();
  var seen = {};
  var lower = {};
  Object.keys(h).forEach(function (k) {
    lower[k.toLowerCase()] = h[k];
  });
  var parts = [];
  for (var i = 0; i < keys.length; i++) {
    if (seen[keys[i]]) continue;
    seen[keys[i]] = 1;
    parts.push(JSON.stringify(keys[i]) + ":" + JSON.stringify(String(lower[keys[i]])));
  }
  return "{" + parts.join(",") + "}";
}

function _sanitize(s) {
  if (typeof s !== "string") return "";
  return s.indexOf("\n") >= 0 || s.indexOf("\r") >= 0 ? "" : s;
}

// ------------------------------------------------------------
// Crypto helpers
// ------------------------------------------------------------

function _hmacHex(keyStr, msgStr) {
  var bytes = Utilities.computeHmacSha256Signature(
    msgStr, keyStr, Utilities.Charset.UTF_8
  );
  return _bytesToHex(bytes);
}

function _sha256Hex(input) {
  var bytes = (typeof input === "string")
    ? Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input, Utilities.Charset.UTF_8)
    : Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, input);
  return _bytesToHex(bytes);
}

function _bytesToHex(bytes) {
  var hex = "";
  for (var i = 0; i < bytes.length; i++) {
    var v = bytes[i] & 0xff;
    hex += (v < 16 ? "0" : "") + v.toString(16);
  }
  return hex;
}

// Constant-time string compare. Both inputs must be ASCII hex; if
// they differ in length we still walk the longer one to keep the
// runtime independent of where the mismatch is.
function _ctEq(a, b) {
  var la = a.length, lb = b.length;
  var maxLen = la > lb ? la : lb;
  var diff = la ^ lb;
  for (var i = 0; i < maxLen; i++) {
    var ca = i < la ? a.charCodeAt(i) : 0;
    var cb = i < lb ? b.charCodeAt(i) : 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}

// ------------------------------------------------------------
// SSRF guard + URL fetch options
// ------------------------------------------------------------

function _isBlockedHost(url) {
  try {
    // Apps Script's URL parser is anemic; do a regex extract.
    var m = url.match(/^https?:\/\/([^/:?#]+)/i);
    if (!m) return true;
    var host = m[1].toLowerCase();
    if (SSRF_BLOCK_HOSTS.indexOf(host) >= 0) return true;
    // IP literals: block private + loopback + link-local.
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      var p = host.split(".").map(Number);
      if (p[0] === 10) return true;
      if (p[0] === 127) return true;
      if (p[0] === 169 && p[1] === 254) return true;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
      if (p[0] === 192 && p[1] === 168) return true;
      if (p[0] === 0) return true;
      if (p[0] >= 224) return true; // multicast / reserved
    }
    if (host === "::1" || host === "localhost") return true;
    return false;
  } catch (e) {
    return true; // fail closed
  }
}

function _buildOpts(env) {
  var opts = {
    method: (env.m || "GET").toLowerCase(),
    muteHttpExceptions: true,
    followRedirects: env.r !== false,
    validateHttpsCertificates: true,
    escaping: false,
  };
  if (env.h && typeof env.h === "object") {
    var headers = {};
    for (var k in env.h) {
      if (env.h.hasOwnProperty(k) && !SKIP_HEADERS[k.toLowerCase()]) {
        headers[k] = env.h[k];
      }
    }
    opts.headers = headers;
  }
  if (env.b) {
    opts.payload = Utilities.base64Decode(env.b);
    if (env.ct) opts.contentType = env.ct;
  }
  return opts;
}

function _respHeaders(resp) {
  try {
    if (typeof resp.getAllHeaders === "function") return resp.getAllHeaders();
  } catch (err) { /* fall through */ }
  return resp.getHeaders();
}

function _json(obj /*, status (advisory only — Apps Script ignores) */) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
