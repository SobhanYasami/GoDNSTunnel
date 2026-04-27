# RelayVPN — User Guide

A free, single-binary local proxy that routes your browser traffic through a
**Google Apps Script relay**, hiding the real destination behind normal-looking
Google traffic. No VPS, no paid service — just a free Google account.

---

## Table of contents

1. [What this tool does](#what-this-tool-does)
2. [How it works](#how-it-works)
3. [Prerequisites](#prerequisites)
4. [Setup, step by step](#setup-step-by-step)
   - [Step 1 — Build the binary](#step-1--build-the-binary)
   - [Step 2 — Generate a strong shared secret](#step-2--generate-a-strong-shared-secret)
   - [Step 3 — Deploy the Apps Script relay](#step-3--deploy-the-apps-script-relay)
   - [Step 4 — Create your config file](#step-4--create-your-config-file)
   - [Step 5 — First run and CA generation](#step-5--first-run-and-ca-generation)
   - [Step 6 — Install the local CA certificate](#step-6--install-the-local-ca-certificate)
   - [Step 7 — Point your browser at the proxy](#step-7--point-your-browser-at-the-proxy)
5. [LAN sharing (optional)](#lan-sharing-optional)
6. [Updating the relay](#updating-the-relay)
7. [Troubleshooting](#troubleshooting)
8. [Configuration reference](#configuration-reference)
9. [Security notes](#security-notes)
10. [Disclaimer](#disclaimer)

---

## What this tool does

You start a small program on your computer. It listens on `127.0.0.1:8085`
(HTTP proxy) and `127.0.0.1:1080` (SOCKS5). Point your browser at it, and
every request you make gets relayed through a Google Apps Script you deploy
to your own free Google account.

To anyone watching the network between your computer and the internet, your
traffic looks like ordinary HTTPS to `www.google.com`. The actual website you
asked for is fetched by your Apps Script and the response is sent back through
the same disguised channel.

Use cases this is built for: testing how domain fronting works, learning about
TLS interception and proxy mechanics, and using censorship-resistant browsing
in places where Google's domains remain reachable.

---

## How it works

```
┌────────────┐       ┌──────────────┐       ┌──────────────────┐       ┌──────────┐
│  Browser   │──────▶│ relayvpn     │──────▶│ Google frontend  │──────▶│  Apps    │──▶ origin website
│ (your PC)  │◀──────│ (this tool)  │◀──────│ (TLS to google.) │◀──────│  Script  │◀── response
└────────────┘       └──────────────┘       └──────────────────┘       └──────────┘
                       │  MITM TLS         SNI = www.google.com         your free
                       │  using local CA   Host: script.google.com      Google account
                       │  HMAC-signed
                       │  envelope
```

Three things to keep in mind:

- The proxy decrypts your HTTPS traffic locally and re-encrypts it for the relay.
  That's why you need to install its local CA certificate as trusted — without
  it your browser will (correctly) refuse to load any site.
- Every request to the relay is signed with a shared secret you set yourself.
  No one else can use your Apps Script deployment, even though it's exposed to
  the public web.
- The Apps Script relay has a quota: about 20,000 requests per Google account
  per day. If you hit it, deploy more relays under different accounts and list
  them all in `script_ids`.

---

## Prerequisites

- A computer running Linux, macOS, or Windows.
- **Go 1.22 or newer** installed. Check with `go version`. Get it from
  <https://go.dev/dl/>.
- A free Google account.
- A modern browser (Firefox or any Chromium-based browser).

---

## Setup, step by step

### Step 1 — Build the binary

Clone the repository and build:

```bash
git clone https://github.com/SobhanYasami/GoDNSTunnel.git
cd GoDNSTunnel
make build
```

You should now have an executable called `relayvpn` (or `relayvpn.exe` on
Windows) in the project root.

If `make` is unavailable, run the underlying command directly:

```bash
go build -trimpath -ldflags '-s -w' -o relayvpn ./cmd/relayvpn
```

### Step 2 — Generate a strong shared secret

This is the password the proxy and the relay use to recognise each other.
Generate something cryptographically random:

```bash
# Linux / macOS
openssl rand -base64 32
```

```powershell
# Windows PowerShell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

Copy the output. You'll paste it in two places — once into the Apps Script and
once into your config file. **They must match exactly.**

A good secret looks like this:

```
hv4Tx9YqM2sB1Kf7Lg8Qe6rZpWnH3uA5cV0jX8oI=
```

Don't reuse a password from anywhere else, and don't commit this string to git.

### Step 3 — Deploy the Apps Script relay

This is the part that takes the most clicks, but you only do it once.

1. Open <https://script.google.com> and sign in with your Google account.
2. Click **New project** (top-left).
3. Delete all the example code in the editor.
4. Open `apps_script/Code.gs` from this repository, copy its entire contents,
   and paste them into the editor.
5. Find this line near the top:

   ```javascript
   const SHARED_SECRET = "CHANGE_ME_TO_A_STRONG_SECRET";
   ```

   Replace `CHANGE_ME_TO_A_STRONG_SECRET` with the secret you generated in
   Step 2. Keep the surrounding quotes.
6. Click the floppy-disk **Save** icon.
7. Click **Deploy** → **New deployment** (top-right).
8. Click the gear icon next to "Select type" and choose **Web app**.
9. Fill in the form:
   - **Description:** anything memorable, e.g. `relay v1`.
   - **Execute as:** `Me (your-email@gmail.com)`.
   - **Who has access:** `Anyone`.
10. Click **Deploy**. Google may ask you to authorise the script — accept the
    prompts. (You'll see a "Google hasn't verified this app" warning because
    it's your own private app; click **Advanced** → **Go to (project name)**.)
11. Once deployed, you'll see a **Deployment ID**. It looks like
    `AKfycb...` and is about 60 characters long. Click **Copy** next to it.

Save that ID. You'll need it in the next step.

### Step 4 — Create your config file

In the project directory:

```bash
cp config.example.json config.json
```

Open `config.json` in a text editor and fill in the two values you just
generated:

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",

  "script_id": "PASTE_YOUR_DEPLOYMENT_ID_HERE",
  "auth_key": "PASTE_YOUR_SHARED_SECRET_HERE",

  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_enabled": true,
  "socks5_port": 1080,

  "log_level": "info"
}
```

The minimum required edits are:

- `script_id` — the Deployment ID from Step 3.
- `auth_key` — the shared secret from Step 2 (must match `SHARED_SECRET` in
  your Apps Script).

Save the file.

### Step 5 — First run and CA generation

Run the proxy:

```bash
./relayvpn -c config.json
```

You should see output similar to:

```
INFO CA ready cert=/.../ca/ca.crt fingerprint=a1b2c3d4...
INFO HTTP proxy listening addr=127.0.0.1:8085 auth=false
INFO SOCKS5 proxy listening addr=127.0.0.1:1080 auth=false
```

On the very first run, the proxy generates a local Certificate Authority at
`ca/ca.crt` and `ca/ca.key`. **Note the SHA-256 fingerprint** printed on
startup — you'll use it to verify the CA after installing it.

Leave the proxy running in this terminal. Open a new one for the next steps.

### Step 6 — Install the local CA certificate

Your browser needs to trust `ca/ca.crt` as a root, or every HTTPS site will
show a certificate error.

> ⚠️ This certificate is **only** for your machine. Do not share `ca/ca.crt`
> or `ca/ca.key` with anyone. The private key is what allows the proxy to
> impersonate any website to your browser; whoever has it can MITM your
> traffic.

#### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ca/ca.crt
```

Or via the GUI: double-click `ca/ca.crt`, find it in **Keychain Access** under
**System**, double-click it, expand **Trust**, and set "When using this
certificate" to **Always Trust**.

#### Linux (Debian/Ubuntu)

```bash
sudo cp ca/ca.crt /usr/local/share/ca-certificates/relayvpn.crt
sudo update-ca-certificates
```

#### Linux (Arch/Fedora)

```bash
sudo cp ca/ca.crt /etc/ca-certificates/trust-source/anchors/relayvpn.crt
sudo update-ca-trust
```

#### Windows

1. Double-click `ca\ca.crt`.
2. Click **Install Certificate**.
3. Choose **Current User** and click **Next**.
4. Select **Place all certificates in the following store** → **Browse** →
   pick **Trusted Root Certification Authorities**.
5. Click **Next** → **Finish**. Confirm the security warning.

#### Firefox (all platforms — required separately)

Firefox uses its own certificate store, even on Linux/macOS:

1. **Settings** → **Privacy & Security** → scroll to **Certificates** →
   **View Certificates**.
2. Open the **Authorities** tab → click **Import**.
3. Select `ca/ca.crt` from the project folder.
4. Tick **Trust this CA to identify websites** → click **OK**.

#### Verify the CA is trusted

After installing, find the certificate in your browser/OS store, and
confirm the SHA-256 thumbprint matches the fingerprint your proxy printed in
Step 5. If they don't match, **stop** — something is wrong, and you should
investigate before continuing.

### Step 7 — Point your browser at the proxy

#### Firefox

**Settings** → search "proxy" → **Network Settings** → **Settings...** →

- Choose **Manual proxy configuration**.
- **HTTP Proxy:** `127.0.0.1`, **Port:** `8085`.
- Tick **Also use this proxy for HTTPS**.
- Click **OK**.

#### Chrome / Edge / Brave

These browsers use the system proxy. The cleanest way is to install a proxy
switcher extension like **SwitchyOmega** or **FoxyProxy** and configure a
profile pointing at `127.0.0.1:8085`. This way you can toggle the proxy on
and off without changing system-wide settings.

If you'd rather use the system setting:

- **macOS:** **System Settings** → **Network** → your active connection →
  **Details** → **Proxies** → enable **Web Proxy (HTTP)** and **Secure Web
  Proxy (HTTPS)**, both `127.0.0.1` port `8085`.
- **Windows:** **Settings** → **Network & Internet** → **Proxy** → **Manual
  proxy setup** → **Use a proxy server** = On, address `127.0.0.1`, port
  `8085`.

#### Test it

Open <https://www.example.com> in the proxied browser. The page should load
normally. If it does, you're done.

For a more visible test, visit a site you know is blocked or geo-fenced from
your normal connection.

---

## LAN sharing (optional)

If you want other devices on your network (phone, tablet, second computer) to
use the same proxy, edit `config.json`:

```json
{
  "lan_sharing": true,
  "proxy_user": "alice",
  "proxy_pass": "a-second-strong-secret-for-the-proxy-itself"
}
```

LAN sharing **requires** `proxy_user` and `proxy_pass` — the proxy will refuse
to start without them. This protects your relay quota from anyone else on the
same network (including coffee-shop wifi, neighbours, or untrusted IoT
devices).

When LAN sharing is on:

- The proxy listens on `0.0.0.0` automatically.
- Find your machine's LAN IP (e.g. `192.168.1.42`).
- On other devices, configure the proxy as `192.168.1.42:8085` (HTTP) and
  enter `alice` / your password when prompted.
- You'll need to install `ca/ca.crt` on every device that uses HTTPS through
  the proxy.

---

## Updating the relay

If you ever change `apps_script/Code.gs`, **editing alone does nothing** —
Apps Script keeps serving the previously deployed version. You must:

1. Click **Deploy** → **New deployment** in the Apps Script editor.
2. Configure it (Web app, Execute as Me, Anyone access).
3. Copy the **new** Deployment ID.
4. Replace `script_id` in `config.json`.
5. Restart `relayvpn`.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `config: auth_key must be ≥24 chars` | Your shared secret is too short. Generate one with `openssl rand -base64 32` and try again. |
| `config: auth_key is still the example placeholder` | You forgot to replace `CHANGE_ME_TO_A_STRONG_SECRET` in `config.json`. |
| Browser shows "Your connection is not private" on every site | The CA certificate isn't installed correctly. Re-do Step 6 for your OS, restart the browser fully (close all windows, including system tray icons). |
| Browser worked, but stopped after I did `git pull` | The CA may have been regenerated. Check that the fingerprint shown on startup matches what's in your trust store. If not, delete the old root and reinstall the new one. |
| `relay error: bad sig` | The `auth_key` in `config.json` doesn't match `SHARED_SECRET` in your Apps Script. They must be byte-for-byte identical. |
| `relay error: stale` | Your computer's clock is more than 60 seconds off real time. Enable NTP / automatic time on your OS. |
| `relay HTTP 502` from the proxy | Apps Script returned an error. Most likely cause: the deployment was never re-created after editing `Code.gs`, or you've hit the daily quota. Create a new deployment and update `script_id`. |
| Proxy works for a while then everything fails | You probably hit the 20,000 req/day Apps Script quota. Wait until midnight Pacific Time, or deploy more relays under additional Google accounts and list them all in `script_ids`. |
| Telegram works on HTTP proxy but not on SOCKS5 | Expected. SOCKS5 clients send raw IPs without hostnames, which we can't relay. Configure Telegram as an HTTP proxy on `127.0.0.1:8085` instead. |
| `lan_sharing=true requires proxy_user and proxy_pass` | LAN sharing without authentication exposes your relay to anyone on your network. Set both fields. This is intentional. |
| First HTTPS site to a new domain is slow | Each new hostname needs a fresh leaf certificate. Subsequent sites under the same parent domain reuse it. |

For detailed logs, run with `"log_level": "debug"` in `config.json`.

---

## Configuration reference

Required:

| Field | Type | Description |
|---|---|---|
| `script_id` | string | Apps Script deployment ID (≥32 chars). |
| `auth_key` | string | Shared secret with the relay (≥24 chars). |

Common:

| Field | Default | Description |
|---|---|---|
| `listen_host` | `127.0.0.1` | Bind address for the proxy. |
| `listen_port` | `8085` | HTTP CONNECT proxy port. |
| `socks5_enabled` | `true` | Enable the SOCKS5 listener. |
| `socks5_port` | `1080` | SOCKS5 listener port. |
| `log_level` | `info` | One of `debug`, `info`, `warn`, `error`. |
| `lan_sharing` | `false` | Bind on all interfaces. **Requires** `proxy_user`/`proxy_pass`. |
| `proxy_user` | `""` | Username for Proxy-Auth Basic and SOCKS5 user/pass. |
| `proxy_pass` | `""` | Password for the same. |

Advanced:

| Field | Default | Description |
|---|---|---|
| `google_ip` | `216.239.38.120` | Google front IP. Try a different one if this is blocked. |
| `front_domain` | `www.google.com` | The hostname your traffic looks like. |
| `script_ids` | `[]` | Multiple deployment IDs for load balancing. All must use the same `auth_key`. |
| `relay_timeout` | `25` | Seconds before a relayed request gives up. |
| `tls_connect_timeout` | `15` | Seconds for the fronted TLS handshake. |
| `tcp_connect_timeout` | `10` | Seconds for direct TCP connects. |
| `max_response_body_bytes` | `209715200` | Hard cap on a single response body (200 MiB). |
| `block_hosts` | `[]` | Hosts that always return 403. Use exact names or `.suffix.com`. |
| `bypass_hosts` | `["localhost", ".local", ".lan", ".home.arpa"]` | Hosts that go direct without MITM. |

Environment variables: `DFT_AUTH_KEY` overrides `auth_key`. Useful for keeping
the secret out of `config.json` on shared machines.

---

## Security notes

- **Treat `config.json` as a secret.** It contains the relay shared key. If it
  leaks, an attacker can use your Google quota until you redeploy with a new
  secret.
- **Treat `ca/ca.key` as a secret.** Anyone with this file can mint a
  certificate impersonating any website to anyone who trusts your CA — which
  is just you, but still: don't share it, don't commit it, don't sync it to
  cloud drives.
- **Install the CA on as few devices as possible.** Each device that trusts
  your CA is a device that can be MITM'd by `ca/ca.key`. If you set up LAN
  sharing for a phone, install the CA only on that phone, not the whole
  household.
- **Don't disable `validate_https` anywhere.** The fronted TLS leg always
  validates the certificate of `front_domain`. Disabling that would expose
  your traffic to MITM by anyone between you and Google.
- **Rotate `auth_key` periodically.** Generate a new one, paste it into
  `config.json` and `SHARED_SECRET`, redeploy the Apps Script.
- **Check the CA fingerprint** on every fresh setup. The proxy prints it on
  startup; compare against your OS/browser cert store.

---

## Disclaimer

**This software is provided strictly for educational, research, and personal
testing purposes.**

By using this tool you agree that:

- You will use it only for **legal** purposes permitted in your jurisdiction.
  You are solely responsible for ensuring your use complies with all
  applicable local, national, and international laws and regulations,
  including computer-misuse, telecommunications, export-control, and
  network-access laws.
- You will not use this tool to commit or facilitate any illegal activity,
  including but not limited to: unauthorised access to computer systems or
  networks, distribution of malicious software, evasion of law-enforcement
  monitoring you are legally required to comply with, harassment, fraud,
  intellectual property infringement, or distribution of illegal content.
- You will not use this tool against networks, services, accounts, or systems
  for which you do not have explicit authorisation.
- You will comply with the **Terms of Service of every third-party platform**
  the tool interacts with. In particular, use of Google Apps Script must
  comply with Google's Terms of Service, Acceptable Use Policy, and
  applicable quotas. Misuse may result in suspension or termination of your
  Google account.
- Domain fronting through Google's infrastructure may itself violate Google's
  policies. Use of this technique is at your own risk.

This software is provided **"as is", without warranty of any kind**, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose, and non-infringement. The authors and
contributors are not liable for any direct, indirect, incidental,
consequential, or other damages arising from the use of, or inability to
use, this software.

If you are a security researcher, penetration tester, or student, this tool
is intended to help you learn how domain fronting, TLS interception, and
proxy mechanics work. Use it on systems and networks you own or have explicit
written permission to test.

**The authors and contributors do not condone any illegal use of this software
and accept no responsibility for misuse.**