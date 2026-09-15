# Proxy Checker

A multi-purpose proxy checker with a live GUI, HTTP API, and system tray integration.

Checks HTTP/HTTPS/SOCKS4/SOCKS5 proxies in parallel, detects anonymity, performs geo
lookup, resolves ASN type via PeeringDB, measures throughput, and exposes results via
HTTP for other applications (MegaBasterd, browsers via PAC, scripts).

Also includes a built-in local SOCKS5 facade that rotates upstream proxies from the
live pool — so any client (Telegram, browser, curl, downloader) can use a single
SOCKS5 endpoint with automatic rotation and failover.

## Features

- **Parallel checking** of HTTP / HTTPS / SOCKS4 / SOCKS5 proxies
- **Live UI updates** — results appear as they are found, not at the end
- **Geo lookup** — country, city, ISP via ip-api.com
- **ASN enrichment** — ASN, ASN name, and provider type via PeeringDB
  - Provider types: `hosting`, `isp`, `nsp`, `business`, `education`,
    `nonprofit`, `government`, `infra`, `proxy`, `mobile`, `unknown`
  - Classification priority: ip-api flags (`hosting`/`proxy`/`mobile`) →
    PeeringDB `info_type` → name heuristic
  - Batched requests (up to 150 ASNs per call, 20 rpm anonymous API limit)
  - Persistent ASN cache (`asn_cache.json`) with 30-day TTL
  - "Ignore cache" and "Clear ASN cache" controls
- **Anonymity detection** — elite / anonymous / transparent
- **Speed test** — second pass, throughput in KB/s (Cloudflare)
- **Grouping** — by country, protocol, anonymity, ISP, ASN type
- **HTTP API** — serve proxies to other apps (MegaBasterd, browsers via PAC, scripts)
- **Local SOCKS5 facade** — one endpoint, rotating upstream from the live pool
  - Rotation on/off, configurable interval and cooldown
  - Sticky per TCP session (one upstream per client connection)
  - Automatic failover: dead proxies go to cooldown, next one is tried
  - Per-upstream cooldown set on selection — proxies rotate in a ring
    instead of ping-ponging between the top two
  - Manual rotation via **Rotate now** button
  - Live status panel: current exit IP + history of last 5 rotations
  - Optional SOCKS5 username/password auth (RFC 1929)
  - Persistent state (`facade_state.json`) — cooldowns and history survive restarts
- **Scrollable UI** — the whole window scrolls, nothing gets cut off
- **HTTP API examples panel** — every endpoint and filter documented in-app
- **System tray** — minimize and keep running in background
- **Auto-refresh** — re-check every N minutes
- **Auto-run on startup** — starts a check automatically if sources are present
- **Persistent state** — loads previous results on startup
- **Sortable table** — click any column to sort
- **English / Russian UI**

## HTTP API

Default: `http://127.0.0.1:8080`

### Endpoints

| Endpoint | Description |
|---|---|
| `/health` | Liveness check, returns `ok` |
| `/stats` | Summary: totals, by country / anonymity / protocol, avg & max speed, avg latency |
| `/asn/stats` | Summary: by `asn_type`, top 50 ASN by proxy count |
| `/proxies` | All proxies, plain text (`scheme://ip:port` per line) |
| `/proxies.json` | All proxies, JSON (full `ProxyResult` objects) |
| `/best` | Sorted by speed, descending |
| `/fast` | Speed > 0, sorted by speed |
| `/fast.json` | Same, JSON |
| `/random` | One random proxy (plain text) |
| `/pac` | PAC file with top-3 proxies + DIRECT fallback |
| `/hosting` | Only `asn_type == hosting` (datacenters / clouds) |
| `/isp` | Only `asn_type == isp` (residential + regional ISPs) |
| `/mobile` | Only `asn_type == mobile` (mobile carriers) |
| `/asn_type/<t>` | Generic: any `asn_type` value |
| `/asn_type/<t>.json` | Same, JSON |

### Filters

Append to any endpoint as query parameters:

| Filter | Example | Description |
|---|---|---|
| `country` | `?country=DE` | ISO country code (exit IP) |
| `asn_type` | `?asn_type=hosting` | Provider type from ASN enrichment |
| `anon` | `?anon=elite` | Anonymity level: `elite` / `anonymous` / `transparent` |
| `proto` | `?proto=socks5` | Protocol: `http` / `https` / `socks4` / `socks5` |
| `elite` | `?elite=1` | Shortcut for `anon=elite` |
| `min_speed` | `?min_speed=500` | Minimum speed, KB/s |
| `max_latency` | `?max_latency=2000` | Maximum latency, ms |
| `limit` | `?limit=10` | Take first N after sorting |
| `sort` | `?sort=latency` | `speed` (default) / `latency` / `random` |

### Examples

```bash
# Top-20 hosting proxies by speed
curl "http://127.0.0.1:8080/best?asn_type=hosting&limit=20"

# Only ISP, alive, in Germany
curl "http://127.0.0.1:8080/isp?country=DE"

# Fast mobile proxies, latency under 2s
curl "http://127.0.0.1:8080/fast?asn_type=mobile&max_latency=2000"

# ASN summary
curl "http://127.0.0.1:8080/asn/stats"

# PAC file for a specific country
curl "http://127.0.0.1:8080/pac?country=FR"
```

## ASN / PeeringDB

Each alive proxy's exit IP is resolved to an ASN via ip-api.com (no extra request —
the fields are added to the existing geo lookup). Unique ASNs are then batched
against the PeeringDB API (`/api/net?asn__in=...`) at up to 150 ASNs per call.

Provider types are assigned by priority:

1. **ip-api flags** — `hosting: true` → `hosting`; `proxy: true` → `proxy`;
   `mobile: true` → `mobile`
2. **PeeringDB `info_type`** — `Content` → `hosting`, `Cable/DSL/ISP` → `isp`,
   `NSP` / `Network Services` → `nsp`, `Enterprise` → `business`,
   `Educational/Research` → `education`, `Non-Profit` → `nonprofit`,
   `Government` → `government`, `Route Server` / `Route Collector` → `infra`
3. **Name heuristic** — if PeeringDB is silent and ip-api has no flags,
   the ASN name is matched against common hosting keywords

Results are cached in `asn_cache.json` with a 30-day TTL. Anonymous PeeringDB
API access is rate-limited to **20 requests per minute per IP**, so requests are
throttled to `PEERINGDB_RPS_DELAY = 3.0` seconds between batches. With a batch
size of 150 ASNs, even large pools resolve in a handful of requests.

If you hit HTTP 429 (rate limit), the response is **not cached** — the next run
retries those ASNs.

## Local SOCKS5 facade

A single SOCKS5 endpoint that rotates through the live proxy pool.

- **Sticky per session** — each client TCP connection uses one upstream,
  then releases it
- **Cooldown on selection** — an upstream is put on cooldown the moment it is
  selected, so the pool rotates in a ring instead of ping-ponging between the
  top two
- **Failover** — dead upstreams go on cooldown, the next candidate is tried
- **Manual rotation** — **Rotate now** button in the UI
- **Status panel** — shows the current exit IP and the history of the last
  5 rotations
- **Auth** — optional SOCKS5 username/password (RFC 1929)
- **Persistence** — `facade_state.json` stores cooldowns and history across
  restarts

### Pointing a client at the facade

```
SOCKS5  127.0.0.1:1080
```

No auth by default. To require auth, set username and password in the Facade
section — clients must then use SOCKS5 user/pass.

Test:

```bash
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

## Requirements

- Python 3.10+
- Tkinter (bundled with most Python installs)

## Install

- Linux / macOS
```bash
git clone https://github.com/sameaslooks/proxy-checker.git
cd proxy-checker

chmod +x run.sh
./run.sh
```

- Windows
```
git clone https://github.com/sameaslooks/proxy-checker.git
cd proxy-checker

run.bat
```

## Configuration

All settings are stored in `proxy_checker_config.yaml` and can be edited
directly or through the GUI. Press **Save config** in the UI to persist
current values.

State files (not config):

- `asn_cache.json` — ASN → PeeringDB metadata (30-day TTL)
- `facade_state.json` — facade cooldowns, active upstream, rotation history

## UI walkthrough

- **Sources** — list of URLs to fetch proxy lists from, or add from a local file
- **Check parameters** — check URL, headers URL, threads, timeout, geo/anon/ASN toggles
- **Speed test** — second pass settings (size, threads, timeout, URL)
- **Grouping** — which dimensions to group saved output by
- **Output** — output folder, JSON name, and per-country / per-param subfolders
- **HTTP server** — port, start/stop, autostart
- **HTTP API examples** — every endpoint and filter, documented inline
- **Facade** — host, port, rotation toggle, interval, cooldown, dial timeout,
  auth, and live status (current exit IP + last 5 rotations)
- **Auto + tray** — auto-refresh interval, tray behavior, language
- **Buttons** — Save / Load config, Start / Stop check, Hide to tray,
  Re-sort table, Export to TXT
- **Log** — everything the checker does
- **Proxies** — sortable table with all results

The whole window scrolls. Mouse wheel works. Nothing gets cut off.

## Output layout

```
output/
├── proxies.json                  # full results, JSON
├── by_country/                   # one .txt per country
│   ├── DE.txt
│   ├── US.txt
│   └── ...
├── by_param/                     # one .txt per (group_by, value)
│   ├── anonymity__elite.txt
│   ├── anonymity__anonymous.txt
│   ├── protocol__socks5.txt
│   └── ...
└── by_asn_type/                  # one .txt per (asn_type, country)
    ├── hosting__DE.txt
    ├── isp__US.txt
    └── ...
```

Each `.txt` file contains one proxy per line: `scheme://ip:port`.

## License

GPLv3 — see `LICENSE`.