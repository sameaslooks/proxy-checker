# Proxy Checker

A multi-purpose proxy checker with a live GUI, HTTP API, and system tray integration.

Checks HTTP/HTTPS/SOCKS4/SOCKS5 proxies in parallel, detects anonymity, performs geo
lookup, measures throughput, and exposes results via HTTP for other applications
(MegaBasterd, browsers via PAC, scripts).

Also includes a built-in local SOCKS5 facade that rotates upstream proxies from the
live pool — so any client (Telegram, browser, curl, downloader) can use a single
SOCKS5 endpoint with automatic rotation and failover.

## Features

- **Parallel checking** of HTTP / HTTPS / SOCKS4 / SOCKS5 proxies
- **Live UI updates** — results appear as they are found, not at the end
- **Geo lookup** — country, city, ISP via ip-api.com
- **Anonymity detection** — elite / anonymous / transparent
- **Speed test** — second pass, throughput in KB/s (Cloudflare)
- **Grouping** — by country, protocol, anonymity, ISP
- **HTTP API** — serve proxies to other apps (MegaBasterd, browsers via PAC, scripts)
- **Local SOCKS5 facade** — one endpoint, rotating upstream from the live pool
  - Rotation on/off, configurable interval and cooldown
  - Sticky per TCP session (one upstream per client connection)
  - Automatic failover: dead proxies go to cooldown, next one is tried
  - Optional SOCKS5 username/password auth (RFC 1929)
  - Persistent state (`facade_state.json`) — cooldowns survive restarts
- **System tray** — minimize and keep running in background
- **Auto-refresh** — re-check every N minutes
- **Auto-run on startup** — starts a check automatically if sources are present
- **Persistent state** — loads previous results on startup
- **Sortable table** — click any column to sort
- **English / Russian UI**

## Requirements

- Python 3.10+
- Tkinter (bundled with most Python installs)

## Install

- Linux / macOS
```bash
git clone https://github.com/sameaslooks/proxy-checker.git
cd proxy-checker
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
chmod +x run.sh
./run.sh
```

- Windows
```
git clone https://github.com/sameaslooks/proxy-checker.git
cd proxy-checker
python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
run.bat
```