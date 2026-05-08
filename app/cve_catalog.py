"""Локальные эвристики + офлайн NVD matching для версий ПО."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("security_combine.cve_catalog")

# (product_key, version_pattern, severity, cve_id, title_suffix)
_CVE_RULES: tuple[tuple[str, re.Pattern[str], str, str, str], ...] = (
    ("nginx", re.compile(r"^1\.(17|16|15|14|13|12|11|10)\."), "high", "CVE-реестр", "nginx 1.10–1.17 (EOL)"),
    ("apache", re.compile(r"^2\.4\.(4[0-9]|5[0-4])"), "medium", "CVE-реестр", "ветка Apache 2.4 c историческими CVE"),
    ("php", re.compile(r"^(5\.|7\.[0-3]\.)"), "high", "CVE-реестр", "устаревшая ветка PHP"),
    ("php", re.compile(r"^7\.4\."), "medium", "EOL notice", "PHP 7.4 снят с поддержки"),
    ("jquery", re.compile(r"^1\."), "high", "CVE-2020-11022 / класс jQuery", "jQuery 1.x устарел; XSS class"),
    ("jquery", re.compile(r"^2\.0\.|^2\.1\.[0-3]"), "medium", "CVE-реестр", "ранние jQuery 2.x"),
    ("drupal", re.compile(r"^7\."), "medium", "Drupal advisory", "Drupal 7 legacy"),
    ("wordpress", re.compile(r"^5\."), "medium", "WordPress advisory", "устаревшая мажорная ветка"),
    ("laravel", re.compile(r"^[5-8]\."), "medium", "Laravel advisory", "старые LTS/ветки"),
    ("symfony", re.compile(r"^[2-4]\."), "medium", "Symfony advisory", "ветки с историческими RCE/XSS"),
    ("tomcat", re.compile(r"^8\."), "medium", "Tomcat advisory", "устаревшая ветка Tomcat 8"),
    ("iis", re.compile(r"^(7|8|9)\."), "medium", "Microsoft advisory", "старые ветки IIS"),
    ("openssl", re.compile(r"^1\.0\.|^1\.1\.0"), "high", "OpenSSL advisory", "устаревшие линейки OpenSSL"),
    ("bitrix", re.compile(r"^(20|21)\."), "medium", "Bitrix advisory", "проверьте обновления ядра Битрикс"),
)

_VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "nginx": re.compile(r"nginx/([\d.]+)", re.I),
    "apache": re.compile(r"apache(?:/|[\s])([\d.]+)", re.I),
    "php": re.compile(r"php/?\s*([\d.]+)", re.I),
    "iis": re.compile(r"microsoft-iis/([\d.]+)", re.I),
    "tomcat": re.compile(r"tomcat(?:/|[\s])([\d.]+)", re.I),
    "drupal": re.compile(r"drupal\s*([\d.]+)", re.I),
    "wordpress": re.compile(r"wordpress\s*([\d.]+)", re.I),
    "laravel": re.compile(r"laravel\s*([\d.]+)", re.I),
    "symfony": re.compile(r"symfony\s*([\d.]+)", re.I),
    "openssl": re.compile(r"openssl(?:/|[\s])([\d.]+)", re.I),
    "bitrix": re.compile(r"bitrix[^0-9]{0,20}([\d.]+)", re.I),
}

_CPE_PRODUCT_MAP: dict[tuple[str, str], str] = {
    ("nginx", "nginx"): "nginx",
    ("apache", "http_server"): "apache",
    ("php", "php"): "php",
    ("drupal", "drupal"): "drupal",
    ("wordpress", "wordpress"): "wordpress",
    ("openssl", "openssl"): "openssl",
    ("laravel", "framework"): "laravel",
    ("symfony", "symfony"): "symfony",
    ("apache", "tomcat"): "tomcat",
    ("microsoft", "iis"): "iis",
    ("bitrix", "site_manager"): "bitrix",
}

_NVD_CACHE: list[dict[str, Any]] = []
_NVD_LOADED = False
_NVD_SOURCE_PATH: str | None = None


def _normalize_severity(raw: str | None) -> str:
    s = (raw or "").strip().lower()
    if s in {"critical", "high", "medium", "low", "info"}:
        return s
    if s in {"moderate"}:
        return "medium"
    return "medium"


def _parse_cpe_23(criteria: str) -> tuple[str, str, str] | None:
    # cpe:2.3:a:vendor:product:version:...
    if not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.split(":")
    if len(parts) < 6:
        return None
    vendor = parts[3].strip().lower()
    product = parts[4].strip().lower()
    version = parts[5].strip()
    mapped = _CPE_PRODUCT_MAP.get((vendor, product))
    if not mapped:
        return None
    return mapped, vendor, version


def _version_tuple(version: str) -> tuple:
    parts = re.split(r"[._-]", version.strip())
    out: list[tuple[int, Any]] = []
    for part in parts:
        if not part:
            continue
        if part.isdigit():
            out.append((0, int(part)))
        else:
            m = re.match(r"(\d+)([A-Za-z].*)", part)
            if m:
                out.append((0, int(m.group(1))))
                out.append((1, m.group(2).lower()))
            else:
                out.append((1, part.lower()))
    return tuple(out)


def _compare_versions(a: str, b: str) -> int:
    ta, tb = _version_tuple(a), _version_tuple(b)
    if ta == tb:
        return 0
    return -1 if ta < tb else 1


def _version_in_range(
    version: str,
    *,
    start_including: str | None,
    start_excluding: str | None,
    end_including: str | None,
    end_excluding: str | None,
) -> bool:
    if start_including and _compare_versions(version, start_including) < 0:
        return False
    if start_excluding and _compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and _compare_versions(version, end_including) > 0:
        return False
    if end_excluding and _compare_versions(version, end_excluding) >= 0:
        return False
    return True


def _extract_nvd_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("CVE_Items"), list):  # NVD 1.1
        return payload["CVE_Items"]
    vulns = payload.get("vulnerabilities")  # NVD 2.0
    if isinstance(vulns, list):
        out: list[dict[str, Any]] = []
        for v in vulns:
            if isinstance(v, dict) and isinstance(v.get("cve"), dict):
                out.append({"cve": v.get("cve"), "configurations": v.get("cve", {}).get("configurations", {})})
        return out
    return []


def _iter_cpe_matches(node: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    cpe_match = node.get("cpe_match") or node.get("cpeMatch")
    if isinstance(cpe_match, list):
        for m in cpe_match:
            if isinstance(m, dict):
                out.append(m)
    children = node.get("children")
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                out.extend(_iter_cpe_matches(child))
    return out


def _extract_nvd_severity(item: dict[str, Any]) -> str:
    impact = item.get("impact", {})
    if isinstance(impact, dict):
        v3 = ((impact.get("baseMetricV3") or {}).get("cvssV3") or {}).get("baseSeverity")
        if isinstance(v3, str):
            return _normalize_severity(v3)
        v2 = ((impact.get("baseMetricV2") or {}).get("cvssV2") or {}).get("baseSeverity")
        if isinstance(v2, str):
            return _normalize_severity(v2)
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {}) if isinstance(cve, dict) else {}
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key)
            if isinstance(arr, list) and arr and isinstance(arr[0], dict):
                sev = ((arr[0].get("cvssData") or {}).get("baseSeverity")) or arr[0].get("baseSeverity")
                if isinstance(sev, str):
                    return _normalize_severity(sev)
    return "medium"


def load_nvd_dump(path: str | Path) -> int:
    p = Path(path)
    if not p.exists():
        return 0
    try:
        payload = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0

    items = _extract_nvd_items(payload if isinstance(payload, dict) else {})
    loaded: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve", {})
        if isinstance(cve, dict):
            cve_id = (
                ((cve.get("CVE_data_meta") or {}).get("ID"))
                or cve.get("id")
                or cve.get("CVE_data_meta", {}).get("ID")
            )
        else:
            cve_id = None
        if not isinstance(cve_id, str) or not cve_id:
            continue
        severity = _extract_nvd_severity(item)
        configurations = item.get("configurations", {})
        nodes = configurations.get("nodes") if isinstance(configurations, dict) else None
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if not isinstance(node, dict):
                continue
            for match in _iter_cpe_matches(node):
                if not bool(match.get("vulnerable", True)):
                    continue
                criteria = match.get("cpe23Uri") or match.get("criteria")
                if not isinstance(criteria, str):
                    continue
                parsed = _parse_cpe_23(criteria)
                if not parsed:
                    continue
                product, _vendor, cpe_version = parsed
                fixed_version = cpe_version if cpe_version not in {"*", "-", ""} else None
                loaded.append(
                    {
                        "product": product,
                        "cve_id": cve_id,
                        "severity": severity,
                        "fixed_version": fixed_version,
                        "start_including": match.get("versionStartIncluding"),
                        "start_excluding": match.get("versionStartExcluding"),
                        "end_including": match.get("versionEndIncluding"),
                        "end_excluding": match.get("versionEndExcluding"),
                    }
                )
    global _NVD_CACHE
    _NVD_CACHE = loaded
    return len(_NVD_CACHE)


def initialize_nvd_cache(path: str | None = None) -> int:
    global _NVD_LOADED, _NVD_SOURCE_PATH
    if _NVD_LOADED:
        return len(_NVD_CACHE)
    chosen = path or os.getenv("SECURITY_COMBINE_NVD_JSON_PATH", "").strip()
    if not chosen:
        base = Path(os.getenv("SECURITY_COMBINE_BASE_DIR", Path(__file__).resolve().parent.parent))
        default_p = base / "data" / "nvdcve-1.1-recent.json"
        if default_p.exists():
            chosen = str(default_p)
    if not chosen:
        _NVD_LOADED = True
        return 0
    loaded = load_nvd_dump(chosen)
    _NVD_SOURCE_PATH = chosen
    _NVD_LOADED = True
    logger.info("NVD cache loaded: %s records from %s", loaded, chosen)
    return loaded


def _find_nvd_matches(product: str, version: str, *, limit: int = 6) -> list[dict[str, Any]]:
    if not _NVD_LOADED:
        initialize_nvd_cache()
    pv = product.lower().strip()
    ver = version.strip()
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in _NVD_CACHE:
        if item.get("product") != pv:
            continue
        fixed = item.get("fixed_version")
        if isinstance(fixed, str) and fixed:
            if fixed != ver:
                continue
        else:
            if not _version_in_range(
                ver,
                start_including=item.get("start_including"),
                start_excluding=item.get("start_excluding"),
                end_including=item.get("end_including"),
                end_excluding=item.get("end_excluding"),
            ):
                continue
        cve_id = str(item.get("cve_id", "")).strip()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        out.append(
            {
                "source": "fingerprint",
                "severity": _normalize_severity(str(item.get("severity", "medium"))),
                "title": f"NVD match: {cve_id} ({product} {version})",
                "evidence": f"Совпадение по офлайн NVD дампу ({_NVD_SOURCE_PATH or 'configured dump'}).",
                "recommendation": "Проверьте CVE и примените патч/обновление для уязвимого диапазона.",
                "affected": f"{product} {version}",
            }
        )
        if len(out) >= limit:
            break
    return out


def findings_for_version(product: str, version: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pv = product.lower().strip()
    ver = version.strip()
    if not ver:
        return out
    for key, rx, sev, cve, note in _CVE_RULES:
        if key != pv:
            continue
        if rx.search(ver):
            out.append(
                {
                    "source": "fingerprint",
                    "severity": sev,
                    "title": f"Версия {product} и известные риски ({cve})",
                    "evidence": f"Обнаружена версия: {ver}. {note}",
                    "recommendation": "Обновите компонент по vendor advisory; сверьте с NVD/внутренней CVE-базой.",
                    "affected": f"{product} {ver}",
                }
            )
            break
    out.extend(_find_nvd_matches(product, version))
    return out


def extract_product_version(product: str, raw_value: str) -> str | None:
    rx = _VERSION_PATTERNS.get(product.lower())
    if not rx:
        return None
    m = rx.search(raw_value or "")
    return m.group(1) if m else None


def extract_versions_from_headers(headers: dict[str, str]) -> list[tuple[str, str, str]]:
    """(product, version, source_header)."""
    out: list[tuple[str, str, str]] = []
    h = {k.lower(): v for k, v in headers.items()}
    candidates = (
        ("server", ("nginx", "apache", "iis", "tomcat", "openssl")),
        ("x-powered-by", ("php", "aspnet", "laravel", "symfony")),
        ("x-generator", ("wordpress", "drupal", "joomla", "symfony")),
        ("x-powered-cms", ("bitrix", "wordpress", "drupal")),
    )
    for header, products in candidates:
        raw = h.get(header, "")
        if not raw:
            continue
        for product in products:
            version = extract_product_version(product, raw)
            if version:
                out.append((product, version, header))
    return out


def extract_nginx_version(server_header: str) -> str | None:
    return extract_product_version("nginx", server_header)
