"""
Расширенный пассивный анализ: фингерпринтинг, security-заголовки, пробы путей, TLS, листинги.
"""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from app.adaptive_http import passive_probe_get
from app.cve_catalog import extract_product_version, extract_versions_from_headers, findings_for_version

# --- Общий формат finding (как в scanner._make_finding) ---


def _f(
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


def _cp_get_probe(checkpoint: dict[str, Any] | None, key: str) -> dict[str, Any] | None:
    if not isinstance(checkpoint, dict):
        return None
    probes = checkpoint.get("probe_cache")
    if not isinstance(probes, dict):
        return None
    item = probes.get(key)
    if not isinstance(item, dict):
        return None
    return item.copy()


def _cp_set_probe(
    checkpoint: dict[str, Any] | None,
    key: str,
    value: dict[str, Any],
    save_checkpoint: Callable[[dict[str, Any]], None] | None,
) -> None:
    if not isinstance(checkpoint, dict):
        return
    probes = checkpoint.setdefault("probe_cache", {})
    if not isinstance(probes, dict):
        probes = {}
        checkpoint["probe_cache"] = probes
    safe = dict(value)
    body = safe.get("body")
    if isinstance(body, str) and len(body) > 200000:
        safe["body"] = body[:200000] + "…[checkpoint-truncated]"
    probes[key] = safe
    checkpoint["updated_at"] = datetime.now(timezone.utc).isoformat()
    if save_checkpoint:
        save_checkpoint(checkpoint)


# Технологии / поверхность для CVE (эвристика, не полная база NVD)
_CVE_SURFACE: tuple[tuple[str, str, str, str], ...] = (
    (
        "wordpress",
        "medium",
        "Стек: WordPress",
        "CMS с большим числом исторических CVE; держите ядро, темы и плагины обновлёнными.",
    ),
    (
        "drupal",
        "medium",
        "Стек: Drupal",
        "Регулярно проверяйте security advisories Drupal и модули.",
    ),
    (
        "joomla",
        "medium",
        "Стек: Joomla",
        "Следите за обновлениями Joomla и расширений.",
    ),
    (
        "php",
        "low",
        "Компонент: PHP (X-Powered-By или cookie)",
        "Устаревшие версии PHP часто имеют известные CVE; ограничьте раскрытие версии.",
    ),
    (
        "aspnet",
        "low",
        "Стек: ASP.NET",
        "Проверьте версию .NET/IIS на известные уязвимости и патчи.",
    ),
    (
        "rails",
        "low",
        "Стек: Ruby on Rails (по путям/заголовкам)",
        "Актуализируйте Rails и зависимости (CVE в экосистеме).",
    ),
    (
        "next",
        "low",
        "Стек: Next.js / React (_next)",
        "Следите за advisory Next.js и npm-зависимостями.",
    ),
    (
        "laravel",
        "low",
        "Стек: Laravel",
        "Обновляйте фреймворк и проверяйте CVE в пакетах Composer.",
    ),
    (
        "django",
        "low",
        "Стек: Django",
        "Обновляйте Django и Python-зависимости.",
    ),
    (
        "bitrix",
        "medium",
        "Стек: 1С-Битрикс",
        "Следите за обновлениями ядра и модулей; закрывайте служебные пути от лишнего доступа.",
    ),
)

_SESSION_COOKIE_MARKERS: frozenset[str] = frozenset(
    {
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "sessionid",
        "sessid",
        "cfid",
        "cftoken",
        "sid",
        "laravel_session",
        "wp-settings",
        "csrftoken",
    }
)

_STATIC_PATH_MARKERS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("/wp-content/", re.compile(r"/wp-content/[\w./-]+", re.I), "WordPress (wp-content)"),
    ("/wp-includes/", re.compile(r"/wp-includes/[\w./-]+", re.I), "WordPress (wp-includes)"),
    ("/assets/react", re.compile(r"/assets/react[\w./-]*", re.I), "React-сборка (assets/react)"),
    ("/static/js/", re.compile(r"/static/js/[\w./-]+", re.I), "Статика JS"),
    ("/_next/", re.compile(r"/_next/static/[\w./-]+", re.I), "Next.js"),
    ("/rails/", re.compile(r"/rails/[\w./-]+", re.I), "Ruby on Rails"),
)


def _collect_tech_tags(
    headers: dict[str, str],
    html: str,
    set_cookie_list: list[str],
) -> dict[str, str]:
    """Ключ -> человекочитаемая метка для отчёта."""
    tags: dict[str, str] = {}
    hlow = {k.lower(): v for k, v in headers.items()}
    server = hlow.get("server", "")
    xpb = hlow.get("x-powered-by", "")

    if server:
        tags["server_banner"] = server.strip()[:200]
        sl = server.lower()
        if "nginx" in sl:
            tags["nginx"] = "nginx"
        if "apache" in sl:
            tags["apache"] = "Apache"
        if "microsoft-iis" in sl or "iis/" in sl:
            tags["iis"] = "Microsoft IIS"
        if "cloudflare" in sl:
            tags["cloudflare"] = "Cloudflare (прокси)"

    if xpb:
        tags["x_powered_by"] = xpb.strip()[:200]
        xl = xpb.lower()
        if "php" in xl:
            tags["php"] = "PHP"
        if "asp.net" in xl:
            tags["aspnet"] = "ASP.NET"

    xcms = hlow.get("x-powered-cms", "")
    if xcms and "bitrix" in xcms.lower():
        tags["bitrix"] = xcms.strip()[:220]
        bx_v = extract_product_version("bitrix", xcms)
        if bx_v:
            tags["bitrix_version"] = bx_v
    if (hlow.get("x-devsrv-cms") or "").lower() == "bitrix":
        tags.setdefault("bitrix", "Bitrix (X-DevSrv-CMS)")
    x_generator = hlow.get("x-generator", "")
    if x_generator:
        tags["x_generator"] = x_generator[:220]
        for product in ("drupal", "wordpress", "joomla", "symfony"):
            ver = extract_product_version(product, x_generator)
            if ver:
                tags[f"{product}_version"] = ver

    html_l = html.lower()
    if "/bitrix/" in html_l or "bitrix.info" in html_l:
        tags.setdefault("bitrix", "Bitrix (разметка /bitrix/)")
    if "wp-content" in html_l or "wp-includes" in html_l:
        tags["wordpress"] = "WordPress (по разметке)"
    if "/_next/" in html_l:
        tags["next"] = "Next.js (по разметке)"
    if "/rails/" in html_l:
        tags["rails"] = "Ruby on Rails (путь)"
    if "generator" in html_l:
        m = re.search(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            html,
            re.I,
        )
        if m:
            tags["meta_generator"] = m.group(1).strip()[:300]
            gen = m.group(1).lower()
            if "wordpress" in gen:
                tags["wordpress"] = "WordPress (meta generator)"
            if "drupal" in gen:
                tags["drupal"] = "Drupal"
            if "joomla" in gen:
                tags["joomla"] = "Joomla"

    cookie_blob = " ".join(set_cookie_list).lower()
    if "laravel_session" in cookie_blob:
        tags["laravel"] = "Laravel (cookie)"
    if "csrftoken" in cookie_blob and "django" in html_l:
        tags["django"] = "Django (эвристика)"
    if "csrfmiddlewaretoken" in html_l or (
        "django" in html_l and ("csrf" in html_l or "__admin" in html_l)
    ):
        tags.setdefault("django", "Django (по разметке)")
    if "phpsessid" in cookie_blob:
        tags["php"] = tags.get("php", "PHP (PHPSESSID)")

    for _prefix, rx, label in _STATIC_PATH_MARKERS:
        if rx.search(html):
            if "wordpress" in label.lower() and "wordpress" in tags:
                continue
            key = label.split("(")[0].strip().lower().replace(" ", "_")[:32]
            tags.setdefault(key, label)

    return tags


def findings_fingerprint(
    headers: dict[str, str],
    html: str,
    set_cookie_list: list[str],
    target_url: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    tags = _collect_tech_tags(headers, html, set_cookie_list)

    if tags:
        lines = [f"{k}: {v}" for k, v in sorted(tags.items())]
        findings.append(
            _f(
                "fingerprint",
                "info",
                "Фингерпринтинг технологий",
                ";\n".join(lines),
                "Сопоставьте версии с CVE-DB и политикой обновлений; уберите лишние баннеры Server/X-Powered-By.",
                target_url,
            )
        )

    emitted: set[str] = set()
    for key, sev, title, rec in _CVE_SURFACE:
        matched = False
        if key == "php" and "php" in tags:
            matched = True
        elif key == "aspnet" and "aspnet" in tags:
            matched = True
        elif key == "rails" and (
            "rails" in tags or any("rails" in str(v).lower() for v in tags.values())
        ):
            matched = True
        elif key == "next" and "next" in tags:
            matched = True
        elif key == "laravel" and "laravel" in tags:
            matched = True
        elif key == "django" and "django" in tags:
            matched = True
        elif key == "bitrix" and "bitrix" in tags:
            matched = True
        elif key in tags:
            matched = True
        if matched and key not in emitted:
            emitted.add(key)
            findings.append(
                _f(
                    "fingerprint",
                    sev,
                    f"Поверхность CVE: {title}",
                    f"Обнаружено по заголовкам/разметке/cookie. {rec}",
                    "Проверьте версии вручную или через зависимый сканер при разрешении владельца.",
                    target_url,
                )
            )

    # Сессионные cookie по имени
    names_found: list[str] = []
    for raw in set_cookie_list:
        part0 = raw.split(";", 1)[0].strip()
        if "=" in part0:
            name = part0.split("=", 1)[0].strip().lower()
            if name in _SESSION_COOKIE_MARKERS or name.endswith("session"):
                names_found.append(part0.split("=", 1)[0].strip())

    if names_found:
        findings.append(
            _f(
                "fingerprint",
                "low",
                "Сессионные cookie (имена)",
                "Set-Cookie: " + ", ".join(sorted(set(names_found))[:20]),
                "Убедитесь в флагах Secure, HttpOnly, SameSite; не раскрывайте лишние детали в именах.",
                target_url,
            )
        )

    meta = {
        "technology_tags": tags,
        "session_cookie_names": names_found,
        "nuclei_cms_tags": nuclei_cms_tags_from_fingerprint(tags),
    }
    return findings, meta


def nuclei_cms_tags_from_fingerprint(tags: dict[str, str]) -> list[str]:
    """Теги шаблонов Nuclei для приоритетного скана (подмножество CMS)."""
    out: list[str] = []
    if "bitrix" in tags:
        out.append("bitrix")
    if "wordpress" in tags:
        out.extend(["wordpress", "wp"])
    if "joomla" in tags:
        out.append("joomla")
    if "drupal" in tags:
        out.append("drupal")
    # уникальные, порядок сохраняем
    seen: set[str] = set()
    uniq = []
    for t in out:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def findings_js_query_params(html: str, target_url: str) -> list[dict[str, Any]]:
    samples = re.findall(r'["\'](/[\w./-]+\.(?:js|css)\?\d{6,})["\']', html, re.I)[:18]
    if not samples:
        return []
    uniq = list(dict.fromkeys(samples))[:12]
    return [
        _f(
            "fingerprint",
            "info",
            "Параметры кэша/сборки у JS/CSS (?цифры)",
            "; ".join(uniq),
            "Часто это timestamp сборки Bitrix/Webpack; сверяйте с политикой раскрытия версий.",
            target_url,
        )
    ]


def findings_banner_versions(headers: dict[str, str], target_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for product, version, source_header in extract_versions_from_headers(headers):
        key = (product, version)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            _f(
                "fingerprint",
                "info",
                f"Определена версия {product}",
                f"{source_header}: {version}",
                "Сверьте с внутренней/offline CVE-базой и актуальными advisory.",
                target_url,
            )
        )
        findings.extend(findings_for_version(product, version))
    return findings


def analyze_headers_info_leak(headers: dict[str, str], target_url: str) -> list[dict[str, Any]]:
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[dict[str, Any]] = []
    leak_headers = (
        ("x-debug-token", "medium", "X-Debug-Token"),
        ("x-debug-token-link", "medium", "X-Debug-Token-Link"),
        ("x-generator", "low", "X-Generator"),
        ("x-drupal-cache", "low", "X-Drupal-Cache"),
        ("x-runtime", "low", "X-Runtime"),
        ("x-aspnet-version", "medium", "X-AspNet-Version"),
        ("x-aspnetmvc-version", "medium", "X-AspNetMvc-Version"),
        ("x-powered-by", "low", "X-Powered-By"),
        ("x-powered-cms", "low", "X-Powered-CMS"),
        ("x-devsrv-cms", "low", "X-DevSrv-CMS"),
    )
    for key, sev, title in leak_headers:
        val = h.get(key)
        if not val:
            continue
        findings.append(
            _f(
                "passive-http",
                sev,
                f"Информационный заголовок: {title}",
                f"{title}: {val[:300]}",
                "Уберите/обобщите технические заголовки на edge/reverse-proxy.",
                target_url,
            )
        )
    return findings


def findings_hidden_fields(html: str, target_url: str) -> list[dict[str, Any]]:
    suspicious = []
    for m in re.finditer(
        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
        html,
        re.I,
    ):
        name = m.group(1).strip()
        low = name.lower()
        if any(x in low for x in ("debug", "test", "token", "secret", "dev", "internal")):
            suspicious.append(name)
    if not suspicious:
        return []
    uniq = sorted(set(suspicious))[:25]
    return [
        _f(
            "fingerprint",
            "low",
            "Подозрительные hidden-поля в HTML",
            ", ".join(uniq),
            "Проверьте, что скрытые поля не раскрывают отладочную или служебную информацию.",
            target_url,
        )
    ]


def _parse_robots_disallow(robots_txt: str) -> list[str]:
    paths: list[str] = []
    for line in robots_txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("disallow:"):
            p = line.split(":", 1)[1].strip()
            if not p or p == "/":
                continue
            if "*" in p or p.startswith("http"):
                continue
            if not p.startswith("/"):
                p = "/" + p
            paths.append(p.split("?")[0].rstrip("/") or "/")
    return list(dict.fromkeys(paths))[:45]


def _parse_sitemap_paths(sitemap_xml: str) -> list[str]:
    paths: list[str] = []
    for m in re.finditer(r"<loc>\s*([^<\s]+)\s*</loc>", sitemap_xml, re.I):
        u = m.group(1).strip()
        try:
            p = urlparse(u)
            path = p.path or "/"
            if path not in paths:
                paths.append(path)
        except Exception:  # noqa: BLE001
            continue
    return paths[:100]


_ADMINISH = ("/admin", "/bitrix", "/wp-", "/manager", "/phpmyadmin", "/login", "/backend")


def findings_seo_surface_expansion(
    base_url: str,
    robots_txt: str | None,
    sitemap_xml: str | None,
    *,
    scan_log_path: Path | None,
    rotation_start: int,
    checkpoint: dict[str, Any] | None = None,
    save_checkpoint: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Disallow из robots + выборка путей из sitemap — точечные GET."""
    findings: list[dict[str, Any]] = []
    raw: list[dict[str, Any]] = []
    idx = rotation_start
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    candidates: list[str] = []
    for p in _parse_robots_disallow(robots_txt or ""):
        pl = p.lower()
        if any(x in pl for x in _ADMINISH):
            candidates.append(p)
    for p in _parse_sitemap_paths(sitemap_xml or "")[:30]:
        if p not in candidates:
            candidates.append(p)
    candidates = candidates[:38]

    for path in candidates:
        url = origin + (path if path.startswith("/") else "/" + path)
        cp_key = f"seo:{path}"
        cached = _cp_get_probe(checkpoint, cp_key)
        if cached is not None:
            pr = cached
        else:
            try:
                pr = passive_probe_get(url, scan_log_path=scan_log_path, rotation_index=idx)
            except Exception as exc:  # noqa: BLE001
                pr = {
                    "ok": False,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "final_url": url,
                    "error": str(exc),
                }
            _cp_set_probe(checkpoint, cp_key, pr, save_checkpoint)
            idx += 1
        st = pr.get("status_code")
        raw.append({"path": path, "status_code": st, "from": "robots/sitemap"})
        if st == 200:
            if "/bitrix/admin" in path.lower():
                findings.append(
                    _f(
                        "passive-probe",
                        "medium",
                        "Доступна зона /bitrix/admin/ (HTTP 200)",
                        "Путь из robots/sitemap отвечает 200 — проверьте аутентификацию.",
                        "Ограничьте IP/VPN; 2FA для администраторов.",
                        url,
                    )
                )
            elif any(x in path.lower() for x in ("/wp-admin", "/administrator", "/admin")):
                findings.append(
                    _f(
                        "passive-probe",
                        "low",
                        f"Чувствительный путь отвечает 200: {path}",
                        "Обнаружен при обходе robots/sitemap.",
                        "Убедитесь, что админка не индексируется и защищена.",
                        url,
                    )
                )
    return findings, raw, idx


def findings_bitrix_version_probe(
    base_url: str,
    *,
    scan_log_path: Path | None,
    rotation_start: int,
    checkpoint: dict[str, Any] | None = None,
    save_checkpoint: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    url = origin + "/bitrix/admin/"
    cp_key = "bitrix:/bitrix/admin/"
    cached = _cp_get_probe(checkpoint, cp_key)
    if cached is not None:
        pr = cached
        next_rotation = rotation_start
    else:
        pr = passive_probe_get(url, scan_log_path=scan_log_path, rotation_index=rotation_start)
        _cp_set_probe(checkpoint, cp_key, pr, save_checkpoint)
        next_rotation = rotation_start + 1
    body = (pr.get("body") or "")[:120000]
    if pr.get("status_code") != 200:
        return findings, next_rotation

    ver = None
    for rx in (
        re.compile(r"1C-Bitrix[^\d]{0,40}(\d{2}\.\d+\.\d+)", re.I),
        re.compile(r"Bitrix\s*Site\s*Manager[^\d]{0,20}(\d{2}\.\d+\.\d+)", re.I),
        re.compile(r"SM_VERSION\s*=\s*[\"']([\d.]+)[\"']", re.I),
        re.compile(r"bx-core.*?(\d{2}\.\d+\.\d+)", re.I),
    ):
        m = rx.search(body)
        if m:
            ver = m.group(1)
            break
    if ver:
        from app.cve_catalog import findings_for_version

        findings.extend(findings_for_version("bitrix", ver))
        findings.append(
            _f(
                "fingerprint",
                "info",
                "Версия 1С-Битрикс (страница входа)",
                f"Эвристика: {ver} (URL {url})",
                "Сверьте с актуальным релизом и бюллетенями безопасности 1С-Битрикс.",
                url,
            )
        )
    else:
        findings.append(
            _f(
                "fingerprint",
                "low",
                "Обнаружена страница /bitrix/admin/ без явной версии в разметке",
                f"HTTP {pr.get('status_code')}, фрагмент: {body[:200].replace(chr(10), ' ')}",
                "Скрывайте признаки CMS; ограничьте доступ к административному разделу.",
                url,
            )
        )
    return findings, next_rotation


def findings_security_headers(headers: dict[str, str], target_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    h = {k.lower(): v for k, v in headers.items()}

    def missing(name: str, severity: str) -> None:
        findings.append(
            _f(
                "passive-http",
                severity,
                f"Отсутствует заголовок {name}",
                f"Ответ не содержит {name}.",
                f"Настройте {name} на уровне приложения или reverse-proxy.",
                target_url,
            )
        )

    # HSTS
    hsts = h.get("strict-transport-security")
    if not hsts:
        missing("Strict-Transport-Security", "high")
    else:
        hstsl = hsts.lower()
        if "max-age=0" in hstsl or re.search(r"max-age=\s*0\b", hstsl):
            findings.append(
                _f(
                    "passive-http",
                    "high",
                    "Слабый Strict-Transport-Security (max-age=0)",
                    hsts[:500],
                    "Уберите max-age=0; задайте длительный max-age (например ≥31536000), при необходимости includeSubDomains.",
                    target_url,
                )
            )
        else:
            m = re.search(r"max-age=(\d+)", hstsl)
            if m:
                age = int(m.group(1))
                if age < 86400:
                    findings.append(
                        _f(
                            "passive-http",
                            "medium",
                            "Короткий max-age в Strict-Transport-Security",
                            hsts[:500],
                            "Рекомендуется max-age не меньше нескольких месяцев (часто 31536000).",
                            target_url,
                        )
                    )

    # CSP
    csp = h.get("content-security-policy") or h.get("content-security-policy-report-only")
    csp_ro = h.get("content-security-policy-report-only")
    if not h.get("content-security-policy"):
        if csp_ro:
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    "Только Content-Security-Policy-Report-Only",
                    "Есть report-only, нет enforce CSP.",
                    "Добавьте строгий Content-Security-Policy после проверки в report-only.",
                    target_url,
                )
            )
        else:
            missing("Content-Security-Policy", "high")
    else:
        cspl = (h.get("content-security-policy") or "").lower()
        if "unsafe-inline" in cspl and "script-src" in cspl:
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    "CSP допускает unsafe-inline для script",
                    h.get("content-security-policy", "")[:800],
                    "Сузьте script-src, используйте nonce/sha256 вместо unsafe-inline где возможно.",
                    target_url,
                )
            )
        if "unsafe-eval" in cspl:
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    "CSP содержит unsafe-eval",
                    h.get("content-security-policy", "")[:800],
                    "Уберите unsafe-eval, если нет жёсткой необходимости.",
                    target_url,
                )
            )
        if re.search(r"default-src\s+['\"]?\*", cspl):
            findings.append(
                _f(
                    "passive-http",
                    "low",
                    "Слабый CSP: default-src *",
                    h.get("content-security-policy", "")[:800],
                    "Ограничьте default-src конкретными источниками.",
                    target_url,
                )
            )

    # X-Frame-Options
    xfo = h.get("x-frame-options")
    if not xfo:
        missing("X-Frame-Options", "medium")
    else:
        xf = xfo.strip().upper()
        if xf not in ("DENY", "SAMEORIGIN"):
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    "Некорректный или устаревший X-Frame-Options",
                    xfo[:200],
                    "Используйте DENY или SAMEORIGIN; для современных браузеров дополните frame-ancestors в CSP.",
                    target_url,
                )
            )

    # X-Content-Type-Options
    xcto = h.get("x-content-type-options")
    if not xcto:
        missing("X-Content-Type-Options", "medium")
    elif "nosniff" not in xcto.lower():
        findings.append(
            _f(
                "passive-http",
                "medium",
                "X-Content-Type-Options без nosniff",
                xcto[:200],
                "Задайте X-Content-Type-Options: nosniff.",
                target_url,
            )
        )

    # Referrer-Policy
    rp = h.get("referrer-policy")
    if not rp:
        missing("Referrer-Policy", "low")
    else:
        rpl = rp.lower().strip()
        if rpl in ("unsafe-url", "origin-when-cross-origin"):
            findings.append(
                _f(
                    "passive-http",
                    "low",
                    "Широкий Referrer-Policy",
                    rp[:200],
                    "Рассмотрите strict-origin-when-cross-origin или no-referrer для чувствительных страниц.",
                    target_url,
                )
            )

    # Permissions-Policy (Feature-Policy устарел)
    pp = h.get("permissions-policy") or h.get("feature-policy")
    if not pp:
        missing("Permissions-Policy", "low")
    else:
        ppl = pp.lower()
        if re.search(r"\(\s*\*\s*\)", ppl) and any(
            x in ppl for x in ("geolocation", "camera", "microphone", "payment")
        ):
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    "Permissions-Policy разрешает чувствительные API широко",
                    pp[:500],
                    "Сузьте списки разрешённых источников для geolocation, camera, microphone и др.",
                    target_url,
                )
            )

    return findings


_SENSITIVE_PATHS: tuple[tuple[str, str], ...] = (
    ("/.git/HEAD", "Git HEAD (возможное раскрытие репозитория)"),
    ("/.env", "Файл окружения .env"),
    ("/.DS_Store", "Метаданные macOS .DS_Store"),
    ("/backup.zip", "Резервная копия backup.zip"),
    ("/backup.tar.gz", "Резервная копия backup.tar.gz"),
    ("/dump.sql", "SQL-дамп"),
    ("/.htaccess", "Конфигурация Apache .htaccess"),
    ("/web.config", "Конфигурация IIS web.config"),
    ("/wp-config.php.bak", "Резервная копия wp-config"),
    ("/.svn/entries", "Subversion metadata"),
    ("/phpinfo.php", "phpinfo"),
    ("/server-status", "Apache server-status"),
    ("/.aws/credentials", "AWS credentials"),
    ("/id_rsa", "Возможный приватный ключ SSH"),
)


def findings_sensitive_and_discovery(
    base_url: str,
    *,
    scan_log_path: Path | None,
    rotation_start: int = 0,
    checkpoint: dict[str, Any] | None = None,
    save_checkpoint: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], int]:
    """Пробы чувствительных путей и вспомогательных (robots/sitemap)."""
    findings: list[dict[str, Any]] = []
    raw_probes: list[dict[str, Any]] = []
    interrupted = False
    errors: list[str] = []
    idx = rotation_start
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    robots_body: str | None = None
    sitemap_body: str | None = None

    for path, label in _SENSITIVE_PATHS:
        url = origin + (path if path.startswith("/") else f"/{path}")
        cp_key = f"sensitive:{path}"
        cached = _cp_get_probe(checkpoint, cp_key)
        if cached is not None:
            pr = cached
        else:
            try:
                pr = passive_probe_get(url, scan_log_path=scan_log_path, rotation_index=idx)
            except Exception as exc:  # noqa: BLE001
                interrupted = True
                msg = f"{path}: {exc}"
                errors.append(msg)
                pr = {
                    "ok": False,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "final_url": url,
                    "error": str(exc),
                }
            _cp_set_probe(checkpoint, cp_key, pr, save_checkpoint)
            idx += 1
        raw_probes.append({"path": path, "label": label, **{k: pr[k] for k in ("status_code", "ok", "error")}})

        st = pr.get("status_code")
        body = (pr.get("body") or "")[:8000]
        if st == 200:
            if path == "/.git/HEAD" and ("ref:" in body.lower() or "refs/heads" in body):
                findings.append(
                    _f(
                        "passive-probe",
                        "high",
                        "Раскрытие: доступен .git/HEAD",
                        body[:400].replace("\n", " "),
                        "Немедленно закройте доступ к .git; проверьте утечку исходников.",
                        url,
                    )
                )
            elif path == "/.env" and ("=" in body) and any(
                x in body.upper() for x in ("API_KEY", "SECRET", "PASSWORD", "DATABASE", "MYSQL", "AWS")
            ):
                findings.append(
                    _f(
                        "passive-probe",
                        "critical",
                        "Раскрытие: .env с признаками секретов",
                        "Обнаружены строки вида KEY=... (фрагмент скрыт).",
                        "Удалите файл из web-root, ротируйте секреты.",
                        url,
                    )
                )
            elif path == "/.env":
                findings.append(
                    _f(
                        "passive-probe",
                        "high",
                        "Раскрытие: ответ 200 на /.env",
                        body[:300].replace("\n", " "),
                        "Убедитесь, что .env недоступен извне.",
                        url,
                    )
                )
            elif path in ("/backup.zip", "/backup.tar.gz", "/dump.sql"):
                findings.append(
                    _f(
                        "passive-probe",
                        "high",
                        f"Возможная утечка: {path} отдаётся с кодом 200",
                        "Тело ответа не проанализировано как архив; требуется ручная проверка.",
                        "Уберите резервные/дамп-файлы из web-root; ограничьте доступ и проверьте утечки.",
                        url,
                    )
                )
            elif path in ("/.htaccess", "/web.config", "/wp-config.php.bak", "/.svn/entries"):
                findings.append(
                    _f(
                        "passive-probe",
                        "medium",
                        f"Раскрытие конфигурации: {path}",
                        body[:400].replace("\n", " "),
                        "Закройте доступ к конфигурационным и резервным файлам.",
                        url,
                    )
                )
            elif path == "/.DS_Store":
                findings.append(
                    _f(
                        "passive-probe",
                        "low",
                        "Доступен .DS_Store",
                        "Файл может раскрывать имена каталогов.",
                        "Удалите .DS_Store из публичной директории и запретите его отдачу на уровне сервера.",
                        url,
                    )
                )
            elif path == "/phpinfo.php" and "phpinfo" in body.lower():
                findings.append(
                    _f(
                        "passive-probe",
                        "medium",
                        "Доступна страница phpinfo",
                        "Раскрывает конфигурацию PHP.",
                        "Удалите/закройте phpinfo.php на продакшене и ограничьте доступ по IP/VPN.",
                        url,
                    )
                )
            elif path == "/server-status" and ("server status" in body.lower() or "apache" in body.lower()):
                findings.append(
                    _f(
                        "passive-probe",
                        "medium",
                        "Возможен доступ к server-status",
                        body[:300].replace("\n", " "),
                        "Ограничьте доступ к модулю status.",
                        url,
                    )
                )
            elif path in ("/.aws/credentials", "/id_rsa"):
                findings.append(
                    _f(
                        "passive-probe",
                        "critical",
                        f"Критичный путь отвечает 200: {path}",
                        "Требуется немедленная проверка содержимого и отзыв ключей.",
                        "Немедленно закройте доступ к файлам ключей и ротируйте все потенциально скомпрометированные секреты.",
                        url,
                    )
                )
        elif st == 403:
            findings.append(
                _f(
                    "passive-probe",
                    "low",
                    f"Путь существует, но закрыт: {path}",
                    "Ответ 403 на чувствительный путь.",
                    "Проверьте, что доступ закрыт осознанно и не зависит от обходов/методов.",
                    url,
                )
            )

    # robots / sitemap — информационно
    for path, title, severity in (
        ("/robots.txt", "robots.txt доступен", "info"),
        ("/sitemap.xml", "sitemap.xml доступен", "info"),
        ("/crossdomain.xml", "crossdomain.xml доступен", "low"),
    ):
        url = origin + path
        cp_key = f"aux:{path}"
        cached = _cp_get_probe(checkpoint, cp_key)
        if cached is not None:
            pr = cached
        else:
            try:
                pr = passive_probe_get(url, scan_log_path=scan_log_path, rotation_index=idx)
            except Exception as exc:  # noqa: BLE001
                interrupted = True
                msg = f"{path}: {exc}"
                errors.append(msg)
                pr = {
                    "ok": False,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "final_url": url,
                    "error": str(exc),
                }
            _cp_set_probe(checkpoint, cp_key, pr, save_checkpoint)
            idx += 1
        raw_probes.append({"path": path, "label": title, **{k: pr[k] for k in ("status_code", "ok", "error")}})
        if pr.get("status_code") == 200:
            full_body = pr.get("body") or ""
            if path == "/robots.txt":
                robots_body = full_body
            elif path == "/sitemap.xml":
                sitemap_body = full_body
            body = full_body[:1500]
            findings.append(
                _f(
                    "passive-probe",
                    severity,
                    title,
                    body.replace("\n", " ")[:500],
                    "Проверьте, не раскрываются ли скрытые пути; crossdomain.xml должен быть минимальным.",
                    url,
                )
            )

    return findings, raw_probes, {"robots_txt": robots_body, "sitemap_xml": sitemap_body, "interrupted": interrupted, "errors": errors[:10]}, idx


_INDEX_OF = re.compile(r"index\s+of\s+/|>\s*index\s+of\s*<", re.I)


def findings_open_directories(
    base_url: str,
    *,
    scan_log_path: Path | None,
    rotation_start: int,
    checkpoint: dict[str, Any] | None = None,
    save_checkpoint: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    paths = (
        "/assets/",
        "/images/",
        "/img/",
        "/static/",
        "/uploads/",
        "/media/",
        "/files/",
        "/public/",
    )
    findings: list[dict[str, Any]] = []
    raw: list[dict[str, Any]] = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    idx = rotation_start
    for path in paths:
        url = origin + path
        cp_key = f"dir:{path}"
        cached = _cp_get_probe(checkpoint, cp_key)
        if cached is not None:
            pr = cached
        else:
            try:
                pr = passive_probe_get(url, scan_log_path=scan_log_path, rotation_index=idx)
            except Exception as exc:  # noqa: BLE001
                pr = {
                    "ok": False,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "final_url": url,
                    "error": str(exc),
                }
            _cp_set_probe(checkpoint, cp_key, pr, save_checkpoint)
            idx += 1
        raw.append({"path": path, "status_code": pr.get("status_code"), "error": pr.get("error")})
        if pr.get("status_code") == 200:
            body = pr.get("body") or ""
            if _INDEX_OF.search(body) or "<title>Index of" in body:
                findings.append(
                    _f(
                        "passive-probe",
                        "medium",
                        f"Возможен листинг каталога: {path}",
                        "В теле ответа обнаружен шаблон листинга (Index of).",
                        "Отключите autoindex; настройте отдачу 403 или индекс-страницу.",
                        url,
                    )
                )
        elif pr.get("status_code") == 403:
            findings.append(
                _f(
                    "passive-probe",
                    "low",
                    f"Каталог отвечает 403: {path}",
                    "Вероятно, путь существует и доступ ограничен.",
                    "Убедитесь, что каталог не раскрывается через альтернативные location/alias.",
                    url,
                )
            )
    return findings, raw, idx


def analyze_tls_deep(host: str, port: int = 443) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Протокол, шифр, валидность сертификата (без полной цепочки в старых API)."""
    findings: list[dict[str, Any]] = []
    meta: dict[str, Any] = {"host": host, "port": port}
    if not host:
        return findings, meta

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                meta["protocol"] = ss.version()
                cipher = ss.cipher()
                meta["cipher"] = cipher
                cert = ss.getpeercert()
                meta["cert_subject"] = dict(x[0] for x in cert.get("subject", ()))
                meta["cert_issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")
                meta["not_after"] = not_after
                meta["not_before"] = not_before

                if meta["protocol"] in ("TLSv1", "TLSv1.1"):
                    findings.append(
                        _f(
                            "tls",
                            "high",
                            "Устаревший протокол TLS",
                            f"Согласовано: {meta['protocol']}",
                            "Отключите TLS 1.0/1.1; оставьте TLS 1.2+.",
                            f"{host}:{port}",
                        )
                    )

                if cipher:
                    name, tlsver, bits = cipher[0], cipher[1], cipher[2]
                    weak = any(
                        x in name.upper()
                        for x in ("NULL", "EXPORT", "RC4", "MD5", "ANON", "IDEA")
                    )
                    if "DES" in name.upper() and "3DES" not in name.upper():
                        weak = True
                    if weak or (bits and bits < 128):
                        findings.append(
                            _f(
                                "tls",
                                "high",
                                "Слабый или устаревший набор шифров",
                                f"{name} ({bits} bit)",
                                "Настройте современные cipher suites (AEAD, отключите RC4/3DES и т.д.).",
                                f"{host}:{port}",
                            )
                        )

                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days = (exp - datetime.now(timezone.utc)).days
                        if days < 0:
                            findings.append(
                                _f(
                                    "tls",
                                    "critical",
                                    "Сертификат просрочен",
                                    f"notAfter={not_after}",
                                    "Выпустите и установите новый сертификат.",
                                    f"{host}:{port}",
                                )
                            )
                        elif days <= 14:
                            findings.append(
                                _f(
                                    "tls",
                                    "high" if days <= 7 else "medium",
                                    "Сертификат скоро истекает",
                                    f"Осталось дней: {days}",
                                    "Продлите сертификат заранее.",
                                    f"{host}:{port}",
                                )
                            )
                    except ValueError:
                        pass

                # Грубая проверка self-signed: совпадение CN/ORG в subject и issuer
                sub = meta["cert_subject"]
                iss = meta["cert_issuer"]
                if sub and iss and sub == iss:
                    findings.append(
                        _f(
                            "tls",
                            "high",
                            "Возможен самоподписанный сертификат",
                            f"subject==issuer: {sub}",
                            "Используйте цепочку от доверенного УЦ для публичных сервисов.",
                            f"{host}:{port}",
                        )
                    )
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            _f(
                "tls",
                "high",
                "Ошибка проверки сертификата (цепочка/хост/срок)",
                str(exc)[:500],
                "Исправьте цепочку, SAN и срок действия; для теста используйте доверенный сертификат.",
                f"{host}:{port}",
            )
        )
        meta["verification_error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        findings.append(
            _f(
                "tls",
                "medium",
                "Не удалось полностью проанализировать TLS",
                str(exc)[:500],
                "Проверьте доступность порта 443 и SNI.",
                f"{host}:{port}",
            )
        )
        meta["error"] = str(exc)

    return findings, meta


def cookie_flags_findings(set_cookie_list: list[str], target_url: str) -> list[dict[str, Any]]:
    if not set_cookie_list:
        return []
    findings: list[dict[str, Any]] = []
    for raw in set_cookie_list[:30]:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {p.split("=", 1)[0].strip().lower(): p for p in parts[1:]}
        missing: list[str] = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        same_site_value = ""
        for part in parts[1:]:
            if part.lower().startswith("samesite="):
                same_site_value = part.split("=", 1)[1].strip()
                break
        if not same_site_value:
            missing.append("SameSite")
        elif same_site_value.lower() not in {"lax", "strict", "none"}:
            missing.append(f"SameSite({same_site_value})")
        if same_site_value.lower() == "none" and "secure" not in attrs:
            missing.append("Secure(required with SameSite=None)")

        if missing:
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    f"Cookie {name}: неполные защитные флаги",
                    "Отсутствуют/слабы: " + ", ".join(dict.fromkeys(missing)),
                    "Для сессионных cookie используйте Secure + HttpOnly + SameSite=Lax/Strict.",
                    target_url,
                )
            )
    return findings
