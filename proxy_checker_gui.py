"""
Proxy Checker — multi-purpose proxy checker with GUI, HTTP API, and system tray.

Checks HTTP/HTTPS/SOCKS4/SOCKS5 proxies in parallel, detects anonymity,
performs geo lookup, measures throughput, and exposes results via HTTP
for other applications (MegaBasterd, browsers via PAC, scripts).

Author: https://github.com/sameaslooks
License: GPLv3
"""

import asyncio
import html as _html
import json
import locale
import os
import queue
import random
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from tkinter import (
    Tk, Toplevel, Frame, Label, Entry, Listbox, Text, StringVar,
    IntVar, END, BOTH, LEFT, RIGHT, X, Y,
    filedialog, messagebox, Scrollbar,
)
from tkinter import ttk

import aiohttp
from aiohttp import web as aioweb
import yaml
from aiohttp_socks import ProxyConnector

from PIL import Image, ImageDraw
import pystray
from pystray import MenuItem as Item, Menu


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IP_PORT_RE = re.compile(
    r"(?:(?P<scheme>https?|socks4|socks5)://)?"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})"
)

CONFIG_FILE = "proxy_checker_config.yaml"
MAX_ROWS = 5000
FLUSH_MS = 200

# Browser-like User-Agent so sites don't reject us with 403
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

PROXY_HEADERS = {
    "via", "x-forwarded-for", "forwarded",
    "x-real-ip", "proxy-connection", "x-proxy-id",
    "x-forwarded-host", "x-forwarded-proto", "forwarded-for",
}


# ---------------------------------------------------------------------------
# Internationalization
# ---------------------------------------------------------------------------

TRANSLATIONS = {
    "en": {
        "title": "Proxy Checker",
        "sources": "Sources (proxy list URLs)",
        "add": "Add",
        "remove": "Remove",
        "from_file": "From file",
        "params": "Check parameters",
        "check_url": "Check URL:",
        "headers_url": "Headers URL:",
        "threads": "Threads:",
        "timeout": "Timeout (s):",
        "detect_geo": "Detect country/city/ISP",
        "detect_anon": "Detect anonymity",
        "speed_group": "Speed test (second pass)",
        "measure_speed": "Measure speed",
        "size_kb": "Size (KB):",
        "speed_threads": "Threads:",
        "speed_timeout": "Timeout (s):",
        "speed_url": "Speed test URL:",
        "grouping": "Group by",
        "output": "Output",
        "folder": "Folder:",
        "json": "JSON:",
        "by_country": "By country:",
        "by_param": "By param:",
        "http_group": "HTTP server (serve proxies to other apps)",
        "port": "Port:",
        "start_server": "Start server",
        "stop_server": "Stop server",
        "autostart": "Autostart on launch",
        "examples": "Examples:",
        "auto_group": "Auto-refresh and tray",
        "auto_refresh": "Auto-refresh every",
        "minutes": "min",
        "hide_tray": "Minimize to tray on close",
        "save_cfg": "Save config",
        "load_cfg": "Load config",
        "start": "▶ START",
        "stop": "■ STOP",
        "resort": "Re-sort",
        "export": "Export to TXT",
        "ready": "Ready",
        "stopped": "stopped",
        "auto_off": "off",
        "no_sources": "Add at least one source",
        "no_results": "No results",
        "check_running": "Check already running",
        "lang": "Language:",
        "log_start": "[*] Starting...",
        "log_loaded_old": "[*] Loaded from previous runs: {n}",
        "log_proxies": "[*] Unique proxies: {n}",
        "log_nothing": "[!] No proxies to check",
        "log_alive": "[+] Alive: {ok} of {total}",
        "log_speed_start": "[*] Measuring speed for {n} proxies ({size} KB, threads {threads})...",
        "log_speed_done": "[+] Speed test complete",
        "log_stopping": "[!] Stop requested...",
        "log_stopped": "Stopping...",
        "log_done": "Done. Alive: {ok} of {total} (checked {done})",
        "log_http_start": "[+] HTTP server: http://127.0.0.1:{port}",
        "log_http_stop": "[*] HTTP server stopped",
        "log_http_port_busy": "[!] HTTP server failed to start (port {port} busy?): {err}",
        "log_http_error": "[!] HTTP server error: {err}",
        "log_http_autostart_fail": "[!] Failed to autostart HTTP server: {err}",
        "log_auto_run": "[*] Auto-refresh triggered",
        "log_auto_skip": "[*] Auto-refresh skipped — check already running",
        "log_cfg_saved": "[*] Config saved to {file}",
        "log_cfg_loaded": "[*] Config loaded",
        "log_export": "[+] Exported: {path}",
        "log_swap": "[*] Snapshot swapped: {n} proxies now live",
        "tray_show": "Show window",
        "tray_hide": "Hide window (tray)",
        "tray_run": "Run check now",
        "tray_quit": "Quit",
        "speed_status": "Speed test: {done}/{total}",
        "auto_status": "every {n} min",
        "state_old": "serving: previous run ({n})",
        "state_new": "serving: current run ({n})",
    },
    "ru": {
        "title": "Proxy Checker",
        "sources": "Источники (URL списков прокси)",
        "add": "Добавить",
        "remove": "Удалить",
        "from_file": "Из файла",
        "params": "Параметры проверки",
        "check_url": "URL проверки:",
        "headers_url": "URL заголовков:",
        "threads": "Потоков:",
        "timeout": "Таймаут (с):",
        "detect_geo": "Определять страну/город/ISP",
        "detect_anon": "Определять анонимность",
        "speed_group": "Замер скорости (второй проход)",
        "measure_speed": "Замерять скорость",
        "size_kb": "Размер (КБ):",
        "speed_threads": "Потоков:",
        "speed_timeout": "Таймаут (с):",
        "speed_url": "URL замера:",
        "grouping": "Группировать по",
        "output": "Куда сохранять",
        "folder": "Папка:",
        "json": "JSON:",
        "by_country": "По странам:",
        "by_param": "По параметрам:",
        "http_group": "HTTP-сервер (отдаёт прокси другим программам)",
        "port": "Порт:",
        "start_server": "Запустить сервер",
        "stop_server": "Остановить сервер",
        "autostart": "Автостарт при запуске",
        "examples": "Примеры:",
        "auto_group": "Автопрогон и трей",
        "auto_refresh": "Автопрогон каждые",
        "minutes": "мин",
        "hide_tray": "Сворачивать в трей при закрытии",
        "save_cfg": "Сохранить конфиг",
        "load_cfg": "Загрузить конфиг",
        "start": "▶ СТАРТ",
        "stop": "■ СТОП",
        "resort": "Пересортировать",
        "export": "Экспорт в TXT",
        "ready": "Готов",
        "stopped": "остановлен",
        "auto_off": "выкл",
        "no_sources": "Добавьте хотя бы один источник",
        "no_results": "Нет результатов",
        "check_running": "Проверка уже идёт",
        "lang": "Язык:",
        "log_start": "[*] Старт...",
        "log_loaded_old": "[*] Загружено из прошлых прогонов: {n}",
        "log_proxies": "[*] Всего уникальных прокси: {n}",
        "log_nothing": "[!] Нет прокси для проверки",
        "log_alive": "[+] Рабочих: {ok} из {total}",
        "log_speed_start": "[*] Замер скорости для {n} прокси ({size} КБ, потоков {threads})...",
        "log_speed_done": "[+] Замер скорости завершён",
        "log_stopping": "[!] Запрошена остановка...",
        "log_stopped": "Останавливаю...",
        "log_done": "Готово. Рабочих: {ok} из {total} (проверено {done})",
        "log_http_start": "[+] HTTP-сервер: http://127.0.0.1:{port}",
        "log_http_stop": "[*] HTTP-сервер остановлен",
        "log_http_port_busy": "[!] HTTP-сервер не запустился (порт {port} занят?): {err}",
        "log_http_error": "[!] Ошибка HTTP-сервера: {err}",
        "log_http_autostart_fail": "[!] Не удалось запустить HTTP-сервер: {err}",
        "log_auto_run": "[*] Автопрогон по таймеру",
        "log_auto_skip": "[*] Автопрогон пропущен — проверка уже идёт",
        "log_cfg_saved": "[*] Конфиг сохранён в {file}",
        "log_cfg_loaded": "[*] Конфиг загружен",
        "log_export": "[+] Экспорт: {path}",
        "log_swap": "[*] Снимок переключён: {n} прокси активны",
        "tray_show": "Показать окно",
        "tray_hide": "Скрыть окно (трей)",
        "tray_run": "Запустить проверку сейчас",
        "tray_quit": "Выход",
        "speed_status": "Замер скорости: {done}/{total}",
        "auto_status": "каждые {n} мин",
        "state_old": "отдаётся: прошлый прогон ({n})",
        "state_new": "отдаётся: текущий прогон ({n})",
    },
}

CURRENT_LANG = "en"


def detect_language():
    """Pick default language from config or system locale."""
    try:
        sys_lang = (locale.getdefaultlocale()[0] or "en").lower()
    except Exception:
        sys_lang = "en"
    return "ru" if sys_lang.startswith("ru") else "en"


def tr(key, **kw):
    lang = CURRENT_LANG if CURRENT_LANG in TRANSLATIONS else "en"
    s = TRANSLATIONS[lang].get(key) or TRANSLATIONS["en"].get(key, key)
    return s.format(**kw) if kw else s


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProxyResult:
    raw: str
    protocol: str
    ip: str
    port: int
    ok: bool = False
    latency_ms: int = 0
    speed_kbps: int = 0
    exit_ip: str = ""
    country: str = ""
    city: str = ""
    isp: str = ""
    anonymity: str = ""
    error: str = ""
    source: str = ""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_proxies(text: str):
    """Extract (scheme, ip, port) from plain text — fallback parser."""
    seen = set()
    for m in IP_PORT_RE.finditer(text):
        scheme = (m.group("scheme") or "http").lower()
        ip = m.group("ip")
        port = int(m.group("port"))
        if not (0 < port < 65536):
            continue
        key = (scheme, ip, port)
        if key in seen:
            continue
        seen.add(key)
        yield scheme, ip, port


def _walk_json_for_proxies(node):
    """Recursively find dicts with ip+port, or strings containing ip:port.

    Only addresses are extracted. Metadata (country, anonymity, speed)
    from external sources is IGNORED — we always re-verify ourselves.
    """
    if isinstance(node, dict):
        ip = node.get("ip") or node.get("addr") or node.get("host")
        port = node.get("port")
        if ip and port:
            try:
                port_int = int(port)
            except (TypeError, ValueError):
                port_int = None
            if port_int and 0 < port_int < 65536:
                proto = (node.get("protocol") or node.get("type")
                         or node.get("scheme") or "http").lower()
                if proto not in ("http", "https", "socks4", "socks5"):
                    proto = "http"
                yield proto, str(ip), port_int
        for v in node.values():
            yield from _walk_json_for_proxies(v)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_json_for_proxies(item)
    elif isinstance(node, str):
        for m in IP_PORT_RE.finditer(node):
            scheme = (m.group("scheme") or "http").lower()
            ip = m.group("ip")
            port = int(m.group("port"))
            if 0 < port < 65536:
                yield scheme, ip, port


def _extract_from_html_rows(html_text):
    """Parse HTML tables where IP and port are in adjacent <td> cells.

    Works for free-proxy-list.net, hidemy.name, spys.one, etc.
    Only addresses are extracted; metadata is re-checked by us.
    """
    ip_re = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")
    port_re = re.compile(r"^(\d{1,5})$")
    proto_re = re.compile(r"\b(HTTP|HTTPS|SOCKS4|SOCKS5)\b", re.IGNORECASE)

    for tr in re.findall(r"<tr\b[^>]*>(.*?)</tr>", html_text,
                         flags=re.IGNORECASE | re.DOTALL):
        cells = re.findall(r"<t[dh]\b[^>]*>(.*?)</t[dh]>", tr,
                           flags=re.IGNORECASE | re.DOTALL)
        if len(cells) < 2:
            continue

        cleaned = []
        for c in cells:
            c = re.sub(r"<[^>]+>", " ", c)
            c = _html.unescape(c)
            c = re.sub(r"\s+", " ", c).strip()
            cleaned.append(c)

        m_ip = ip_re.match(cleaned[0])
        m_port = port_re.match(cleaned[1])
        if not (m_ip and m_port):
            continue

        ip = m_ip.group(1)
        port = int(m_port.group(1))
        if not (0 < port < 65536):
            continue

        scheme = "http"
        row_text = " ".join(cleaned[2:])
        pm = proto_re.search(row_text)
        if pm:
            scheme = pm.group(1).lower()
            # "HTTPS" -> "https"; "SOCKS4" -> "socks4"; "SOCKS5" -> "socks5"
            # "HTTP" -> "http". All lowercase already by .lower().
        yield scheme, ip, port


def extract_proxies_from_any(text: str):
    """Extract (scheme, ip, port) from plain text, JSON, or HTML.

    Order:
      1. HTML tables (must run before tag stripping)
      2. JSON (if the text looks like JSON)
      3. Plain text after stripping tags

    Metadata from external sources is IGNORED — we always re-verify.
    Deduplicates within the call.
    """
    seen = set()
    stripped = text.strip()

    # 1. HTML table rows
    lower = text.lower()
    if "<tr" in lower and "<td" in lower:
        for scheme, ip, port in _extract_from_html_rows(text):
            key = (scheme, ip, port)
            if key not in seen:
                seen.add(key)
                yield scheme, ip, port

    # 2. JSON
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            for scheme, ip, port in _walk_json_for_proxies(data):
                key = (scheme, ip, port)
                if key not in seen:
                    seen.add(key)
                    yield scheme, ip, port
        except Exception:
            pass

    # 3. Plain text after stripping script/style and all tags
    cleaned = re.sub(r"<script\b[^>]*>.*?</script>", " ", text,
                     flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<style\b[^>]*>.*?</style>", " ", cleaned,
                     flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = _html.unescape(cleaned)

    for scheme, ip, port in parse_proxies(cleaned):
        key = (scheme, ip, port)
        if key in seen:
            continue
        seen.add(key)
        yield scheme, ip, port


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}
    return {}


def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)


def load_json_results(path: str):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = []
        for d in data:
            if not d.get("ok"):
                continue
            fields = {k: d.get(k) for k in ProxyResult.__dataclass_fields__}
            out.append(ProxyResult(**fields))
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Network operations
# ---------------------------------------------------------------------------

async def fetch_source(session, url, timeout=30):
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": DEFAULT_UA},
        ) as r:
            r.raise_for_status()
            return url, await r.text(errors="ignore")
    except Exception as e:
        return url, f"__ERROR__:{e}"


async def collect_proxies(sources, log):
    proxies = {}
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, u) for u in sources]
        for coro in asyncio.as_completed(tasks):
            url, text = await coro
            if text.startswith("__ERROR__:"):
                log(f"[!] {url}: {text[10:]}")
                continue
            count = 0
            for scheme, ip, port in extract_proxies_from_any(text):
                key = (scheme, ip, port)
                if key not in proxies:
                    proxies[key] = url
                    count += 1
            log(f"[+] {url}: +{count} new (total {len(proxies)})")
    return proxies


async def get_my_ip(session, log):
    for url in ("http://api.ipify.org?format=json", "http://httpbin.org/ip"):
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": DEFAULT_UA},
            ) as r:
                data = await r.json(content_type=None)
                ip = data.get("ip") or data.get("origin")
                if ip:
                    log(f"[*] My real IP: {ip}")
                    return ip
        except Exception as e:
            log(f"[!] Failed to get my IP via {url}: {e}")
    log("[!] Could not determine my IP — transparent won't be distinguished from anonymous")
    return ""


async def geo_lookup(session, ip):
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,isp,query"},
            timeout=aiohttp.ClientTimeout(total=10),
            headers={"User-Agent": DEFAULT_UA},
        ) as r:
            data = await r.json(content_type=None)
            if data.get("status") == "success":
                return data.get("country", ""), data.get("city", ""), data.get("isp", "")
    except Exception:
        pass
    return "", "", ""


async def detect_anonymity(session_plain, scheme, ip, port, headers_url, my_ip, timeout):
    # SOCKS4/5 do not add HTTP headers — from the site's perspective, it's direct
    if scheme in ("socks4", "socks5"):
        return "elite"
    try:
        async with session_plain.get(
            headers_url,
            proxy=f"{scheme}://{ip}:{port}",
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": DEFAULT_UA},
        ) as r:
            data = await r.json(content_type=None)
        headers = {k.lower(): str(v) for k, v in (data.get("headers") or {}).items()}
        if not headers:
            return ""
        seen_ip_blob = " ".join(
            headers.get(k, "") for k in
            ("x-forwarded-for", "x-real-ip", "forwarded", "forwarded-for", "via")
        )
        has_proxy_headers = any(k in headers for k in PROXY_HEADERS)
        if my_ip and my_ip in seen_ip_blob:
            return "transparent"
        if has_proxy_headers:
            return "anonymous"
        return "elite"
    except Exception:
        return ""


async def check_one(session_plain, scheme, ip, port, check_url, timeout, source):
    res = ProxyResult(
        raw=f"{scheme}://{ip}:{port}",
        protocol=scheme,
        ip=ip,
        port=port,
        source=source,
    )
    start = time.perf_counter()
    try:
        if scheme in ("socks4", "socks5"):
            connector = ProxyConnector.from_url(f"{scheme}://{ip}:{port}", rdns=True)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": DEFAULT_UA},
            ) as s:
                async with s.get(check_url) as r:
                    data = await r.json(content_type=None)
        else:
            async with session_plain.get(
                check_url,
                proxy=f"{scheme}://{ip}:{port}",
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": DEFAULT_UA},
            ) as r:
                data = await r.json(content_type=None)

        res.latency_ms = int((time.perf_counter() - start) * 1000)
        res.exit_ip = data.get("origin") or data.get("ip") or data.get("query") or ""
        if data.get("status") == "success":
            res.country = data.get("country", "") or res.country
            res.city = data.get("city", "") or res.city
            res.isp = data.get("isp", "") or res.isp
        res.ok = True
    except Exception as e:
        res.error = str(e)[:160]
    return res


async def measure_speed(session_plain, scheme, ip, port, test_url, timeout, size_bytes):
    """Download up to size_bytes through the proxy and return KB/s."""
    received = 0
    start = time.perf_counter()
    try:
        if scheme in ("socks4", "socks5"):
            connector = ProxyConnector.from_url(f"{scheme}://{ip}:{port}", rdns=True)
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": DEFAULT_UA},
            )
        else:
            session = session_plain

        kwargs = {} if scheme in ("socks4", "socks5") else {"proxy": f"{scheme}://{ip}:{port}"}
        try:
            async with session.get(
                test_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"User-Agent": DEFAULT_UA},
                **kwargs,
            ) as r:
                async for chunk in r.content.iter_chunked(16 * 1024):
                    received += len(chunk)
                    if received >= size_bytes:
                        break
        finally:
            if scheme in ("socks4", "socks5"):
                await session.close()

        elapsed = time.perf_counter() - start
        if elapsed <= 0 or received == 0:
            return 0
        return int((received / 1024) / elapsed)
    except Exception:
        return 0


async def check_many(proxies, cfg, log, progress_cb, on_result, stop_event, on_speed=None):
    check_url = cfg["check_url"]
    headers_url = cfg.get("headers_url", "http://httpbin.org/headers")
    timeout = cfg["timeout"]
    concurrency = cfg["concurrency"]
    do_geo = cfg.get("geo_lookup", True)
    do_anon = cfg.get("detect_anonymity", True)
    do_speed = cfg.get("measure_speed", True)
    speed_concurrency = cfg.get("speed_concurrency", 50)
    speed_timeout = cfg.get("speed_timeout", 12)
    speed_size_bytes = int(cfg.get("speed_size_kb", 200)) * 1024
    speed_url = cfg.get("speed_test_url",
                        "https://speed.cloudflare.com/__down?bytes=200000")

    total = len(proxies)
    done = 0
    results = []
    ok_results = []

    sem_check = asyncio.Semaphore(concurrency)
    sem_enrich = asyncio.Semaphore(max(20, concurrency // 4))

    connector = aiohttp.TCPConnector(limit=concurrency * 2, ttl_dns_cache=300)
    async with aiohttp.ClientSession(connector=connector) as session_plain:
        my_ip = await get_my_ip(session_plain, log) if do_anon else ""

        async def one(scheme, ip, port, source):
            if stop_event.is_set():
                return None
            async with sem_check:
                if stop_event.is_set():
                    return None
                r = await check_one(
                    session_plain, scheme, ip, port, check_url, timeout, source
                )
            if r.ok:
                async with sem_enrich:
                    if not stop_event.is_set():
                        if do_geo and not r.country and r.exit_ip:
                            r.country, r.city, r.isp = await geo_lookup(
                                session_plain, r.exit_ip
                            )
                        if do_anon and not r.anonymity:
                            r.anonymity = await detect_anonymity(
                                session_plain, r.protocol, r.ip, r.port,
                                headers_url, my_ip, timeout,
                            )
                on_result(r)
            return r

        tasks = [
            asyncio.create_task(one(s, i, p, src))
            for (s, i, p), src in proxies.items()
        ]

        try:
            for coro in asyncio.as_completed(tasks):
                if stop_event.is_set():
                    break
                r = await coro
                if r is None:
                    continue
                done += 1
                progress_cb(done, total)
                results.append(r)
                if r.ok:
                    ok_results.append(r)
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        # Second pass: speed test
        if do_speed and ok_results and not stop_event.is_set():
            log(tr("log_speed_start",
                   n=len(ok_results),
                   size=int(speed_size_bytes / 1024),
                   threads=speed_concurrency))
            sem_speed = asyncio.Semaphore(speed_concurrency)
            speed_done = 0
            speed_total = len(ok_results)

            async def speed_task(r):
                nonlocal speed_done
                async with sem_speed:
                    if stop_event.is_set():
                        return
                    r.speed_kbps = await measure_speed(
                        session_plain, r.protocol, r.ip, r.port,
                        speed_url, speed_timeout, speed_size_bytes,
                    )
                speed_done += 1
                if on_speed:
                    on_speed(r, speed_done, speed_total)

            speed_tasks = [asyncio.create_task(speed_task(r)) for r in ok_results]
            await asyncio.gather(*speed_tasks, return_exceptions=True)
            log(tr("log_speed_done"))

    return results


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

def make_http_app(app: "App") -> aioweb.Application:
    routes = aioweb.RouteTableDef()

    def _current_data():
        """Return the data that endpoints should serve right now.

        - While a check is running: previous snapshot (proxies_old)
        - After a check completes: the result of the last check (proxies_old,
          which was swapped from proxies_new at the end)
        """
        with app.proxies_lock:
            return list(app.proxies_old)

    def _filter(req, force_sort=None, force_min_speed=None):
        country = req.query.get("country", "").upper()
        anon = req.query.get("anon", "").lower()
        proto = req.query.get("proto", "").lower()
        try:
            limit = int(req.query.get("limit", "0") or 0)
        except ValueError:
            limit = 0
        try:
            min_speed = int(req.query.get("min_speed", "0") or 0)
        except ValueError:
            min_speed = 0
        try:
            max_latency = int(req.query.get("max_latency", "0") or 0)
        except ValueError:
            max_latency = 0
        if force_min_speed is not None:
            min_speed = max(min_speed, force_min_speed)
        only_elite = req.query.get("elite", "").lower() in ("1", "true", "yes")
        sort_by = (force_sort or req.query.get("sort", "speed")).lower()

        data = _current_data()

        if country:
            data = [r for r in data if (r.country or "").upper() == country]
        if anon:
            data = [r for r in data if (r.anonymity or "").lower() == anon]
        if proto:
            data = [r for r in data if r.protocol == proto]
        if only_elite:
            data = [r for r in data if r.anonymity == "elite"]
        if min_speed > 0:
            data = [r for r in data if (r.speed_kbps or 0) >= min_speed]
        if max_latency > 0:
            data = [r for r in data if (r.latency_ms or 10**9) <= max_latency]

        if sort_by == "latency":
            data.sort(key=lambda r: r.latency_ms or 10**9)
        elif sort_by == "random":
            random.shuffle(data)
        else:  # "speed" — default
            data.sort(key=lambda r: r.speed_kbps or 0, reverse=True)

        if limit > 0:
            data = data[:limit]
        return data

    @routes.get("/health")
    async def health(req):
        return aioweb.Response(text="ok")

    @routes.get("/stats")
    async def stats(req):
        data = _current_data()
        by_country, by_anon, by_proto = {}, {}, {}
        speeds, latencies = [], []
        for r in data:
            by_country[r.country or "?"] = by_country.get(r.country or "?", 0) + 1
            by_anon[r.anonymity or "?"] = by_anon.get(r.anonymity or "?", 0) + 1
            by_proto[r.protocol] = by_proto.get(r.protocol, 0) + 1
            if r.speed_kbps:
                speeds.append(r.speed_kbps)
            if r.latency_ms:
                latencies.append(r.latency_ms)
        with app.proxies_lock:
            checking = app.checking
            new_count = len(app.proxies_new)
        return aioweb.json_response({
            "total": len(data),
            "by_country": by_country,
            "by_anonymity": by_anon,
            "by_protocol": by_proto,
            "speed_kbps_avg": int(sum(speeds) / len(speeds)) if speeds else 0,
            "speed_kbps_max": max(speeds) if speeds else 0,
            "latency_ms_avg": int(sum(latencies) / len(latencies)) if latencies else 0,
            "checking": checking,
            "checking_alive": new_count,
        })

    @routes.get("/proxies")
    async def proxies(req):
        data = _filter(req)
        body = "\n".join(f"{r.protocol}://{r.ip}:{r.port}" for r in data)
        return aioweb.Response(text=body, content_type="text/plain")

    @routes.get("/proxies.json")
    async def proxies_json(req):
        data = _filter(req)
        return aioweb.json_response([asdict(r) for r in data])

    @routes.get("/best")
    async def best(req):
        # Top-N by download speed (alias for /proxies with default sort)
        data = _filter(req, force_sort="speed")
        body = "\n".join(f"{r.protocol}://{r.ip}:{r.port}" for r in data)
        return aioweb.Response(text=body, content_type="text/plain")

    @routes.get("/fast")
    async def fast(req):
        data = _filter(req, force_sort="speed", force_min_speed=1)
        body = "\n".join(f"{r.protocol}://{r.ip}:{r.port}" for r in data)
        return aioweb.Response(text=body, content_type="text/plain")

    @routes.get("/fast.json")
    async def fast_json(req):
        data = _filter(req, force_sort="speed", force_min_speed=1)
        return aioweb.json_response([asdict(r) for r in data])

    @routes.get("/random")
    async def random_one(req):
        data = _filter(req, force_sort="random")
        if not data:
            return aioweb.Response(status=404, text="no proxies")
        r = random.choice(data)
        return aioweb.Response(text=f"{r.protocol}://{r.ip}:{r.port}")

    @routes.get("/pac")
    async def pac(req):
        # For browsers: sort by latency, not speed
        data = _filter(req, force_sort="latency")
        if not data:
            pac_text = "function FindProxyForURL(url, host) { return 'DIRECT'; }"
        else:
            first = data[0]
            scheme = {"http": "PROXY", "https": "HTTPS",
                      "socks4": "SOCKS", "socks5": "SOCKS5"}.get(first.protocol, "PROXY")
            pac_text = (
                "function FindProxyForURL(url, host) {\n"
                f"    return '{scheme} {first.ip}:{first.port}; DIRECT';\n"
                "}\n"
            )
        return aioweb.Response(
            text=pac_text,
            content_type="application/x-ns-proxy-autoconfig",
        )

    webapp = aioweb.Application()
    webapp.add_routes(routes)
    return webapp


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App:
    def __init__(self, root: Tk):
        global CURRENT_LANG

        self.root = root
        root.title(tr("title"))
        root.geometry("1100x960")

        self.cfg = load_config()
        # Language: config > system locale
        CURRENT_LANG = self.cfg.get("language") or detect_language()

        self.log_queue = queue.Queue()
        self.results = []
        self.worker_thread = None
        self.stop_event = threading.Event()

        self.row_buffer = []
        self.ok_count = 0
        self.total_count = 0
        self.done_count = 0

        # Two independent states:
        #   proxies_old — what endpoints serve right now (before/while check)
        #   proxies_new — accumulating during a run; becomes old on finish
        self.proxies_lock = threading.Lock()
        self.proxies_old = []
        self.proxies_new = []
        self.checking = False

        self._iid_by_key = {}

        self.http_server = False
        self.http_runner = None
        self.http_loop = None
        self.http_thread = None

        self.tray_icon = None
        self._auto_job = None

        self.auto_enabled = IntVar(value=0)
        self.auto_interval = IntVar(value=30)
        self.hide_on_close = IntVar(value=1)
        self.auto_http = IntVar(value=1)

        self.measure_speed = IntVar(value=1)
        self.speed_size_kb = IntVar(value=200)
        self.speed_concurrency = IntVar(value=50)
        self.speed_timeout = IntVar(value=12)
        self.speed_test_url = StringVar(
            value="https://speed.cloudflare.com/__down?bytes=200000"
        )

        self.lang_var = StringVar(value=CURRENT_LANG)

        self._sort_state = {}

        self._build_ui()
        self._load_cfg_into_ui()
        self._load_old_snapshot()

        self.root.protocol("WM_DELETE_WINDOW", self._real_quit)
        self._setup_tray()

        self.root.after(100, self._drain_log)
        self.root.after(FLUSH_MS, self._flush_rows)

        if self.auto_http.get():
            self.root.after(500, self._auto_start_http)
        if self.auto_enabled.get():
            self._toggle_auto()

    # ---------- UI ----------
    def _build_ui(self):
        # Sources
        f_src = ttk.LabelFrame(self.root, text=tr("sources"))
        f_src.pack(fill=X, padx=8, pady=4)

        self.src_listbox = Listbox(f_src, height=5)
        self.src_listbox.pack(side=LEFT, fill=BOTH, expand=True, padx=4, pady=4)
        sb = Scrollbar(f_src, command=self.src_listbox.yview)
        sb.pack(side=LEFT, fill=Y)
        self.src_listbox.config(yscrollcommand=sb.set)

        f_src_btns = Frame(f_src)
        f_src_btns.pack(side=RIGHT, fill=Y, padx=4)
        ttk.Button(f_src_btns, text=tr("add"), command=self.add_source).pack(fill=X, pady=2)
        ttk.Button(f_src_btns, text=tr("remove"), command=self.del_source).pack(fill=X, pady=2)
        ttk.Button(f_src_btns, text=tr("from_file"), command=self.add_sources_from_file).pack(fill=X, pady=2)

        # Check params
        f_par = ttk.LabelFrame(self.root, text=tr("params"))
        f_par.pack(fill=X, padx=8, pady=4)

        row = Frame(f_par); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("check_url")).pack(side=LEFT)
        self.check_url = StringVar(value="http://ip-api.com/json?fields=status,country,city,isp,query")
        Entry(row, textvariable=self.check_url).pack(side=LEFT, fill=X, expand=True, padx=4)

        row = Frame(f_par); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("headers_url")).pack(side=LEFT)
        self.headers_url = StringVar(value="http://httpbin.org/headers")
        Entry(row, textvariable=self.headers_url).pack(side=LEFT, fill=X, expand=True, padx=4)

        row = Frame(f_par); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("threads")).pack(side=LEFT)
        self.concurrency = IntVar(value=200)
        Entry(row, textvariable=self.concurrency, width=6).pack(side=LEFT, padx=4)
        Label(row, text=tr("timeout")).pack(side=LEFT, padx=(12, 0))
        self.timeout = IntVar(value=8)
        Entry(row, textvariable=self.timeout, width=6).pack(side=LEFT, padx=4)
        self.geo_var = IntVar(value=1)
        ttk.Checkbutton(row, text=tr("detect_geo"), variable=self.geo_var).pack(side=LEFT, padx=12)
        self.anon_var = IntVar(value=1)
        ttk.Checkbutton(row, text=tr("detect_anon"), variable=self.anon_var).pack(side=LEFT, padx=6)

        # Speed test
        f_speed = ttk.LabelFrame(self.root, text=tr("speed_group"))
        f_speed.pack(fill=X, padx=8, pady=4)

        row = Frame(f_speed); row.pack(fill=X, padx=4, pady=2)
        ttk.Checkbutton(row, text=tr("measure_speed"), variable=self.measure_speed).pack(side=LEFT)
        Label(row, text=tr("size_kb")).pack(side=LEFT, padx=(12, 0))
        Entry(row, textvariable=self.speed_size_kb, width=6).pack(side=LEFT, padx=4)
        Label(row, text=tr("speed_threads")).pack(side=LEFT, padx=(12, 0))
        Entry(row, textvariable=self.speed_concurrency, width=6).pack(side=LEFT, padx=4)
        Label(row, text=tr("speed_timeout")).pack(side=LEFT, padx=(12, 0))
        Entry(row, textvariable=self.speed_timeout, width=6).pack(side=LEFT, padx=4)

        row = Frame(f_speed); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("speed_url")).pack(side=LEFT)
        Entry(row, textvariable=self.speed_test_url).pack(side=LEFT, fill=X, expand=True, padx=4)

        # Grouping
        f_grp = ttk.LabelFrame(self.root, text=tr("grouping"))
        f_grp.pack(fill=X, padx=8, pady=4)
        self.group_vars = {
            "country": IntVar(value=1),
            "protocol": IntVar(value=1),
            "anonymity": IntVar(value=1),
            "isp": IntVar(value=0),
        }
        for k, v in self.group_vars.items():
            ttk.Checkbutton(f_grp, text=k, variable=v).pack(side=LEFT, padx=8, pady=4)

        # Output
        f_out = ttk.LabelFrame(self.root, text=tr("output"))
        f_out.pack(fill=X, padx=8, pady=4)

        row = Frame(f_out); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("folder")).pack(side=LEFT)
        self.out_dir = StringVar(value=os.path.abspath("output"))
        Entry(row, textvariable=self.out_dir).pack(side=LEFT, fill=X, expand=True, padx=4)
        ttk.Button(row, text="...", width=3, command=self.choose_dir).pack(side=LEFT)

        row = Frame(f_out); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("json")).pack(side=LEFT)
        self.out_json = StringVar(value="proxies.json")
        Entry(row, textvariable=self.out_json, width=25).pack(side=LEFT, padx=4)
        Label(row, text=tr("by_country")).pack(side=LEFT, padx=(12, 0))
        self.out_country = StringVar(value="by_country")
        Entry(row, textvariable=self.out_country, width=15).pack(side=LEFT, padx=4)
        Label(row, text=tr("by_param")).pack(side=LEFT, padx=(12, 0))
        self.out_param = StringVar(value="by_param")
        Entry(row, textvariable=self.out_param, width=15).pack(side=LEFT, padx=4)

        # HTTP server
        f_http = ttk.LabelFrame(self.root, text=tr("http_group"))
        f_http.pack(fill=X, padx=8, pady=4)

        row = Frame(f_http); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("port")).pack(side=LEFT)
        self.http_port = IntVar(value=8080)
        Entry(row, textvariable=self.http_port, width=6).pack(side=LEFT, padx=4)
        self.btn_http = ttk.Button(row, text=tr("start_server"), command=self.toggle_http)
        self.btn_http.pack(side=LEFT, padx=8)
        self.http_status = StringVar(value=tr("stopped"))
        Label(row, textvariable=self.http_status).pack(side=LEFT, padx=8)
        ttk.Checkbutton(row, text=tr("autostart"),
                        variable=self.auto_http).pack(side=LEFT, padx=12)

        row = Frame(f_http); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("examples")).pack(side=LEFT)
        for txt in (
            "/best?country=DE&limit=10",
            "/fast?min_speed=500&limit=10",
            "/fast?country=DE",
            "/proxies?min_speed=500&sort=speed",
            "/proxies?country=DE&sort=latency",
            "/proxies.json?anon=elite",
            "/random?country=FR",
            "/pac?country=DE",
            "/stats",
        ):
            Label(row, text=txt, fg="gray").pack(side=LEFT, padx=4)

        # Auto + tray
        f_auto = ttk.LabelFrame(self.root, text=tr("auto_group"))
        f_auto.pack(fill=X, padx=8, pady=4)

        row = Frame(f_auto); row.pack(fill=X, padx=4, pady=2)
        ttk.Checkbutton(row, text=tr("auto_refresh"),
                        variable=self.auto_enabled,
                        command=self._toggle_auto).pack(side=LEFT)
        Entry(row, textvariable=self.auto_interval, width=6).pack(side=LEFT, padx=4)
        Label(row, text=tr("minutes")).pack(side=LEFT)
        self.auto_status = StringVar(value=tr("auto_off"))
        Label(row, textvariable=self.auto_status, fg="gray").pack(side=LEFT, padx=8)

        row = Frame(f_auto); row.pack(fill=X, padx=4, pady=2)
        Label(row, text=tr("lang")).pack(side=LEFT)
        lang_combo = ttk.Combobox(row, textvariable=self.lang_var,
                                  values=["en", "ru"], width=5, state="readonly")
        lang_combo.pack(side=LEFT, padx=4)
        lang_combo.bind("<<ComboboxSelected>>", self._on_lang_change)

        # Buttons
        f_run = Frame(self.root)
        f_run.pack(fill=X, padx=8, pady=6)
        ttk.Button(f_run, text=tr("save_cfg"), command=self.save_cfg_from_ui).pack(side=LEFT, padx=2)
        ttk.Button(f_run, text=tr("load_cfg"), command=self.load_cfg_into_ui).pack(side=LEFT, padx=2)
        self.btn_start = ttk.Button(f_run, text=tr("start"), command=self.start)
        self.btn_start.pack(side=LEFT, padx=20)
        self.btn_stop = ttk.Button(f_run, text=tr("stop"), command=self.stop, state="disabled")
        self.btn_stop.pack(side=LEFT, padx=2)
        ttk.Button(f_run, text=tr("tray_hide"), command=self.hide_to_tray).pack(side=LEFT, padx=2)
        ttk.Button(f_run, text=tr("resort"), command=self.resort_tree).pack(side=LEFT, padx=2)
        ttk.Button(f_run, text=tr("export"), command=self.export_txt).pack(side=LEFT, padx=2)

        self.progress = ttk.Progressbar(f_run, mode="determinate")
        self.progress.pack(side=LEFT, fill=X, expand=True, padx=8)

        self.status_var = StringVar(value=tr("ready"))
        Label(self.root, textvariable=self.status_var, anchor="w").pack(fill=X, padx=10)

        # Log
        f_log = ttk.LabelFrame(self.root, text="Log")
        f_log.pack(fill=BOTH, expand=True, padx=8, pady=4)
        self.log = Text(f_log, height=5, wrap="none")
        self.log.pack(side=LEFT, fill=BOTH, expand=True, padx=4, pady=4)
        sb2 = Scrollbar(f_log, command=self.log.yview)
        sb2.pack(side=LEFT, fill=Y)
        self.log.config(yscrollcommand=sb2.set)

        # Results
        f_res = ttk.LabelFrame(self.root, text="Proxies")
        f_res.pack(fill=BOTH, expand=True, padx=8, pady=4)
        cols = ("raw", "protocol", "latency_ms", "speed_kbps", "exit_ip",
                "country", "city", "isp", "anonymity", "source")
        self.tree = ttk.Treeview(f_res, columns=cols, show="headings", height=10)
        for c in cols:
            self.tree.heading(c, text=c, command=lambda col=c: self._sort_by_column(col))
            self.tree.column(c, width=100, anchor="w")
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        sb3 = Scrollbar(f_res, command=self.tree.yview)
        sb3.pack(side=LEFT, fill=Y)
        self.tree.config(yscrollcommand=sb3.set)

    # ---------- Language ----------
    def _on_lang_change(self, event=None):
        global CURRENT_LANG
        CURRENT_LANG = self.lang_var.get()
        messagebox.showinfo(
            "Language",
            "Language changed. Restart the app to apply." if CURRENT_LANG == "en"
            else "Язык изменён. Перезапустите приложение.",
        )

    # ---------- Sources ----------
    def add_source(self):
        dlg = Toplevel(self.root); dlg.title(tr("add")); dlg.geometry("600x100")
        v = StringVar()
        Entry(dlg, textvariable=v).pack(fill=X, padx=8, pady=8)
        def ok():
            u = v.get().strip()
            if u:
                self.src_listbox.insert(END, u)
            dlg.destroy()
        ttk.Button(dlg, text="OK", command=ok).pack(pady=4)
        dlg.transient(self.root); dlg.grab_set()

    def del_source(self):
        for i in reversed(self.src_listbox.curselection()):
            self.src_listbox.delete(i)

    def add_sources_from_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.src_listbox.insert(END, line)

    # ---------- Config ----------
    def _load_cfg_into_ui(self):
        c = self.cfg
        for u in c.get("sources", []):
            self.src_listbox.insert(END, u)
        if "check_url" in c: self.check_url.set(c["check_url"])
        if "headers_url" in c: self.headers_url.set(c["headers_url"])
        if "concurrency" in c: self.concurrency.set(c["concurrency"])
        if "timeout" in c: self.timeout.set(c["timeout"])
        self.geo_var.set(1 if c.get("geo_lookup", True) else 0)
        self.anon_var.set(1 if c.get("detect_anonymity", True) else 0)
        self.measure_speed.set(1 if c.get("measure_speed", True) else 0)
        if "speed_size_kb" in c: self.speed_size_kb.set(c["speed_size_kb"])
        if "speed_concurrency" in c: self.speed_concurrency.set(c["speed_concurrency"])
        if "speed_timeout" in c: self.speed_timeout.set(c["speed_timeout"])
        if "speed_test_url" in c: self.speed_test_url.set(c["speed_test_url"])
        out = c.get("output", {})
        if out.get("dir"): self.out_dir.set(out["dir"])
        if out.get("json"): self.out_json.set(out["json"])
        if out.get("by_country_dir"): self.out_country.set(out["by_country_dir"])
        if out.get("by_param_dir"): self.out_param.set(out["by_param_dir"])
        for k, v in self.group_vars.items():
            v.set(1 if k in c.get("group_by", []) else 0)
        if "http_port" in c: self.http_port.set(c["http_port"])
        self.auto_http.set(1 if c.get("auto_http", True) else 0)
        self.auto_enabled.set(1 if c.get("auto_enabled", False) else 0)
        if "auto_interval" in c: self.auto_interval.set(c["auto_interval"])
        self.hide_on_close.set(1 if c.get("hide_on_close", True) else 0)

    def load_cfg_into_ui(self):
        self.cfg = load_config()
        self.src_listbox.delete(0, END)
        self._load_cfg_into_ui()
        self._log(tr("log_cfg_loaded"))

    def save_cfg_from_ui(self):
        save_config(self._gather_cfg())
        self._log(tr("log_cfg_saved", file=CONFIG_FILE))

    def _gather_cfg(self):
        return {
            "sources": list(self.src_listbox.get(0, END)),
            "check_url": self.check_url.get(),
            "headers_url": self.headers_url.get(),
            "concurrency": int(self.concurrency.get()),
            "timeout": int(self.timeout.get()),
            "geo_lookup": bool(self.geo_var.get()),
            "detect_anonymity": bool(self.anon_var.get()),
            "measure_speed": bool(self.measure_speed.get()),
            "speed_size_kb": int(self.speed_size_kb.get()),
            "speed_concurrency": int(self.speed_concurrency.get()),
            "speed_timeout": int(self.speed_timeout.get()),
            "speed_test_url": self.speed_test_url.get(),
            "group_by": [k for k, v in self.group_vars.items() if v.get()],
            "http_port": int(self.http_port.get()),
            "auto_http": bool(self.auto_http.get()),
            "auto_enabled": bool(self.auto_enabled.get()),
            "auto_interval": int(self.auto_interval.get()),
            "hide_on_close": bool(self.hide_on_close.get()),
            "language": self.lang_var.get(),
            "output": {
                "dir": self.out_dir.get(),
                "json": self.out_json.get(),
                "by_country_dir": self.out_country.get(),
                "by_param_dir": self.out_param.get(),
            },
        }

    def choose_dir(self):
        d = filedialog.askdirectory()
        if d:
            self.out_dir.set(d)

    # ---------- Log ----------
    def _log(self, msg):
        self.log_queue.put(msg)

    def _drain_log(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log.insert(END, msg + "\n")
                self.log.see(END)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_log)

    # ---------- Live updates ----------
    def _on_result(self, r: ProxyResult):
        """Called for every working proxy during a run. Writes ONLY to proxies_new."""
        self.ok_count += 1
        self.row_buffer.append(r)
        with self.proxies_lock:
            self.proxies_new.append(r)
        self.root.after(0, self._update_title)

    def _on_speed(self, r: ProxyResult, done: int, total: int):
        def upd():
            key = (r.protocol, r.ip, r.port)
            iid = self._iid_by_key.get(key)
            if iid and self.tree.exists(iid):
                self.tree.set(iid, "speed_kbps", str(r.speed_kbps))
            self.status_var.set(tr("speed_status", done=done, total=total))
        self.root.after(0, upd)

    def _update_title(self):
        self.root.title(f"{tr('title')} — {self.ok_count}/{self.total_count} "
                        f"({self.done_count})")

    def _flush_rows(self):
        if self.row_buffer:
            for r in self.row_buffer:
                iid = self.tree.insert("", END, values=(
                    r.raw, r.protocol, r.latency_ms, r.speed_kbps, r.exit_ip,
                    r.country, r.city, r.isp, r.anonymity, r.source,
                ))
                self._iid_by_key[(r.protocol, r.ip, r.port)] = iid
            self.row_buffer.clear()

            children = self.tree.get_children()
            if len(children) > MAX_ROWS:
                for item in children[:len(children) - MAX_ROWS]:
                    self.tree.delete(item)
                    for k, v in list(self._iid_by_key.items()):
                        if v == item:
                            del self._iid_by_key[k]

            children = self.tree.get_children()
            if children:
                self.tree.see(children[-1])

        self.root.after(FLUSH_MS, self._flush_rows)

    # ---------- Sorting ----------
    def _sort_by_column(self, col):
        reverse = self._sort_state.get(col, False)
        self._sort_state[col] = not reverse

        def key_for(iid):
            val = self.tree.set(iid, col)
            if col in ("port", "latency_ms", "speed_kbps"):
                try:
                    return (0, int(val) if val != "" else 10**9)
                except ValueError:
                    return (0, 10**9)
            if col == "anonymity":
                order = {"elite": 0, "anonymous": 1, "transparent": 2, "": 3}
                return (0, order.get(val, 9))
            return (1, (val or "").lower())

        items = list(self.tree.get_children(""))
        items.sort(key=key_for, reverse=reverse)
        for idx, iid in enumerate(items):
            self.tree.move(iid, "", idx)

    def resort_tree(self):
        """Default sort: elite first, then by speed (desc), then by latency (asc)."""
        items = [(self.tree.item(i, "values"), i) for i in self.tree.get_children()]
        order = {"elite": 0, "anonymous": 1, "transparent": 2, "": 3}
        def key(pair):
            vals = pair[0]
            anon = vals[8] if len(vals) > 8 else ""
            try:
                speed = int(vals[3]) if len(vals) > 3 and vals[3] != "" else 0
            except Exception:
                speed = 0
            try:
                lat = int(vals[2]) if len(vals) > 2 and vals[2] != "" else 10**9
            except Exception:
                lat = 10**9
            return (order.get(anon, 9), -speed, lat)
        items.sort(key=key)
        for idx, (vals, iid) in enumerate(items):
            self.tree.move(iid, "", idx)
        self._log("[*] Table re-sorted (elite → speed → latency)")

    # ---------- HTTP server ----------
    def toggle_http(self):
        if self.http_server:
            self.stop_http_server()
            self.btn_http.config(text=tr("start_server"))
            self.http_status.set(tr("stopped"))
        else:
            self.start_http_server()
            self.btn_http.config(text=tr("stop_server"))
            self.http_status.set(f"http://127.0.0.1:{self.http_port.get()}")

    def _auto_start_http(self):
        try:
            self.start_http_server()
            self.btn_http.config(text=tr("stop_server"))
            self.http_status.set(f"http://127.0.0.1:{self.http_port.get()}")
        except Exception as e:
            self._log(tr("log_http_autostart_fail", err=e))

    def start_http_server(self):
        if self.http_server:
            return
        port = int(self.http_port.get())
        loop = asyncio.new_event_loop()
        self.http_loop = loop
        app_web = make_http_app(self)

        def _run():
            asyncio.set_event_loop(loop)
            try:
                runner = aioweb.AppRunner(app_web)
                loop.run_until_complete(runner.setup())
                site = aioweb.TCPSite(runner, "127.0.0.1", port)
                loop.run_until_complete(site.start())
                self.http_runner = runner
                self._log(tr("log_http_start", port=port))
            except OSError as e:
                self._log(tr("log_http_port_busy", port=port, err=e))
                self.http_server = False
                self.root.after(0, lambda: self.btn_http.config(text=tr("start_server")))
                self.root.after(0, lambda: self.http_status.set("error"))
                return
            except Exception as e:
                self._log(tr("log_http_error", err=e))
                self.http_server = False
                return

            try:
                loop.run_forever()
            finally:
                # Cleanup on exit
                try:
                    loop.run_until_complete(runner.cleanup())
                except Exception:
                    pass
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()

        self.http_thread = threading.Thread(target=_run, daemon=True)
        self.http_thread.start()
        self.http_server = True

    def stop_http_server(self):
        if not self.http_server or not self.http_loop:
            return
        loop = self.http_loop
        runner = self.http_runner

        async def _stop():
            if runner:
                await runner.cleanup()

        try:
            fut = asyncio.run_coroutine_threadsafe(_stop(), loop)
            fut.result(timeout=5)
        except Exception:
            pass

        # Stop the loop
        try:
            loop.call_soon_threadsafe(loop.stop)
        except Exception:
            pass

        # Wait for the thread to actually finish
        if self.http_thread and self.http_thread.is_alive():
            self.http_thread.join(timeout=3)

        self.http_server = False
        self.http_runner = None
        self.http_thread = None
        self.http_loop = None
        self._log(tr("log_http_stop"))

    # ---------- Tray ----------
    def _make_tray_image(self):
        img = Image.new("RGB", (64, 64), (30, 30, 30))
        d = ImageDraw.Draw(img)
        d.rectangle([8, 8, 56, 56], outline=(0, 200, 100), width=4)
        d.ellipse([22, 22, 42, 42], fill=(0, 200, 100))
        return img

    def _setup_tray(self):
        menu = Menu(
            Item(tr("tray_show"), self._tray_show, default=True),
            Item(tr("tray_hide"), self._tray_hide),
            Item(tr("tray_run"), self._tray_run),
            Item(tr("tray_quit"), self._tray_quit),
        )
        self.tray_icon = pystray.Icon(
            "proxy_checker", self._make_tray_image(), tr("title"), menu
        )
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _tray_show(self, icon=None, item=None):
        self.root.after(0, self.root.deiconify)

    def _tray_hide(self, icon=None, item=None):
        self.root.after(0, self.root.withdraw)

    def _tray_run(self, icon=None, item=None):
        self.root.after(0, self.start)

    def _tray_quit(self, icon=None, item=None):
        self.root.after(0, self._real_quit)

    def hide_to_tray(self):
        self.root.withdraw()

    def _real_quit(self):
        try:
            if self.worker_thread and self.worker_thread.is_alive():
                self.stop_event.set()
        except Exception:
            pass
        try:
            self.stop_http_server()
        except Exception:
            pass
        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass
        try:
            # Force-quit after a short grace period
            self.root.after(200, self.root.destroy)
        except Exception:
            self.root.destroy()

    # ---------- Auto-refresh ----------
    def _toggle_auto(self):
        if self.auto_enabled.get():
            self.auto_status.set(tr("auto_status", n=self.auto_interval.get()))
            self._schedule_auto()
        else:
            self.auto_status.set(tr("auto_off"))
            if self._auto_job:
                try:
                    self.root.after_cancel(self._auto_job)
                except Exception:
                    pass
                self._auto_job = None

    def _schedule_auto(self):
        if not self.auto_enabled.get():
            return
        interval_ms = max(1, int(self.auto_interval.get())) * 60 * 1000
        self._auto_job = self.root.after(interval_ms, self._auto_run)

    def _auto_run(self):
        self._auto_job = None
        if not (self.worker_thread and self.worker_thread.is_alive()):
            self._log(tr("log_auto_run"))
            self.start()
        else:
            self._log(tr("log_auto_skip"))
        self._schedule_auto()

    # ---------- Load old snapshot ----------
    def _load_old_snapshot(self):
        base = self.out_dir.get()
        json_path = os.path.join(base, self.out_json.get())
        snapshot = list(load_json_results(json_path))
        seen = {(r.protocol, r.ip, r.port) for r in snapshot}

        country_dir = os.path.join(base, self.out_country.get())
        if os.path.isdir(country_dir):
            for fname in os.listdir(country_dir):
                if not fname.endswith(".txt"):
                    continue
                country = fname[:-4]
                path = os.path.join(country_dir, fname)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            parsed = next(parse_proxies(line), None)
                            if not parsed:
                                continue
                            scheme, ip, port = parsed
                            key = (scheme, ip, port)
                            if key in seen:
                                continue
                            seen.add(key)
                            snapshot.append(ProxyResult(
                                raw=f"{scheme}://{ip}:{port}",
                                protocol=scheme, ip=ip, port=port,
                                ok=True, country=country,
                            ))
                except Exception:
                    pass

        with self.proxies_lock:
            self.proxies_old = snapshot
        if snapshot:
            self._log(tr("log_loaded_old", n=len(snapshot)))

    # ---------- Run check ----------
    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self._log(tr("check_running"))
            return
        cfg = self._gather_cfg()
        if not cfg["sources"]:
            messagebox.showwarning(tr("title"), tr("no_sources"))
            return
        save_config(cfg)

        self.results = []
        self.tree.delete(*self.tree.get_children())
        self._iid_by_key.clear()
        self.row_buffer.clear()
        self.ok_count = 0
        self.done_count = 0
        self.total_count = 0
        self.progress["value"] = 0
        self.status_var.set(tr("log_start"))
        self.stop_event.clear()
        self._log(tr("log_start"))

        # Start a new run: clear only the new buffer, keep the old snapshot.
        with self.proxies_lock:
            self.proxies_new = []
            self.checking = True

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")

        self.worker_thread = threading.Thread(
            target=self._run_async, args=(cfg,), daemon=True
        )
        self.worker_thread.start()

    def stop(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_event.set()
            self._log(tr("log_stopping"))
            self.status_var.set(tr("log_stopped"))

    def _run_async(self, cfg):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._pipeline(cfg))
        except Exception as e:
            self._log(f"[!] Pipeline error: {e}")
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            loop.close()
            self.root.after(0, self._on_finished)

    def _on_finished(self):
        # Swap: new becomes old. Endpoints will now serve the fresh results.
        with self.proxies_lock:
            self.proxies_old = list(self.proxies_new)
            self.proxies_new = []
            self.checking = False
            n = len(self.proxies_old)
        self._log(tr("log_swap", n=n))

        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.status_var.set(
            tr("log_done", ok=self.ok_count, total=self.total_count, done=self.done_count)
        )
        self.root.title(f"{tr('title')} — {self.ok_count}/{self.total_count}")

    async def _pipeline(self, cfg):
        proxies = await collect_proxies(cfg["sources"], self._log)
        self.total_count = len(proxies)
        self._log(tr("log_proxies", n=len(proxies)))
        if not proxies:
            self._log(tr("log_nothing"))
            return

        def progress(done, total):
            self.done_count = done
            self.root.after(
                0,
                lambda d=done, t=total: self.progress.configure(maximum=t, value=d)
            )

        def on_result(r):
            self._on_result(r)

        def on_speed(r, done, total):
            self._on_speed(r, done, total)

        results = await check_many(
            proxies, cfg, self._log, progress, on_result, self.stop_event, on_speed
        )
        ok = [r for r in results if r.ok]
        self._log(tr("log_alive", ok=len(ok), total=len(results)))
        self.results = ok
        self._save_all(results, cfg)

    # ---------- Saving ----------
    def _save_all(self, results, cfg):
        out = cfg["output"]
        base = out["dir"]
        os.makedirs(base, exist_ok=True)

        json_path = os.path.join(base, out["json"])
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, ensure_ascii=False, indent=2)
        self._log(f"[+] JSON: {json_path}")

        by_country_dir = os.path.join(base, out["by_country_dir"])
        os.makedirs(by_country_dir, exist_ok=True)
        buckets = defaultdict(list)
        for r in results:
            if r.ok:
                buckets[r.country or "unknown"].append(r)
        for country, items in buckets.items():
            safe = re.sub(r"[^\w\-.]", "_", country)
            p = os.path.join(by_country_dir, f"{safe}.txt")
            with open(p, "w", encoding="utf-8") as f:
                for r in items:
                    f.write(f"{r.raw}\n")
        self._log(f"[+] By country: {by_country_dir}")

        by_param_dir = os.path.join(base, out["by_param_dir"])
        os.makedirs(by_param_dir, exist_ok=True)
        for param in cfg.get("group_by", []):
            bb = defaultdict(list)
            for r in results:
                if not r.ok:
                    continue
                val = getattr(r, param, "") or "unknown"
                bb[str(val)].append(r)
            for val, items in bb.items():
                safe = re.sub(r"[^\w\-.]", "_", val)
                p = os.path.join(by_param_dir, f"{param}__{safe}.txt")
                with open(p, "w", encoding="utf-8") as f:
                    for r in items:
                        f.write(f"{r.raw}\n")
        self._log(f"[+] By param: {by_param_dir}")

    def export_txt(self):
        if not self.results:
            messagebox.showinfo(tr("title"), tr("no_results"))
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for r in self.results:
                if r.ok:
                    f.write(f"{r.raw}\n")
        self._log(tr("log_export", path=path))


def main():
    root = Tk()
    try:
        root.call("tk", "scaling", 1.2)
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()