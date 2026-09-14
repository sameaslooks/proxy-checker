# Proxy Checker

A multi-purpose proxy checker with a live GUI, HTTP API, and system tray integration.

## Features

- **Parallel checking** of HTTP / HTTPS / SOCKS4 / SOCKS5 proxies
- **Live UI updates** — results appear as they are found, not at the end
- **Geo lookup** — country, city, ISP via ip-api.com
- **Anonymity detection** — elite / anonymous / transparent
- **Speed test** — second pass, throughput in KB/s (Cloudflare)
- **Grouping** — by country, protocol, anonymity, ISP
- **HTTP API** — serve proxies to other apps (MegaBasterd, browsers via PAC, scripts)
- **System tray** — minimize and keep running in background
- **Auto-refresh** — re-check every N minutes
- **Persistent state** — loads previous results on startup
- **Sortable table** — click any column to sort
- **English / Russian UI**

## Requirements

- Python 3.10+
- Tkinter (bundled with most Python installs)

## Install

- Linux // macOS
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
```bash
git clone https://github.com/sameaslooks/proxy-checker.git
cd proxy-checker
python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
run.bat
```