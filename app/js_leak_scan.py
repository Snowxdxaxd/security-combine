"""
Извлечение внешних и встроенных JS, эвристики секретов и версий библиотек.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from app.adaptive_http import passive_probe
from app.cve_catalog import findings_for_version

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Возможный AWS Access Key в JS"),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"), "Возможный Google API key в JS"),
    ("openai", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "Похоже на API-ключ формата sk-*"),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "Похоже на GitHub token"),
    ("heroku", re.compile(r"(?i)heroku[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9]{20,}[\"']"), "Похоже на Heroku API key"),
    ("azure_storage", re.compile(r"(?i)azure[_-]?storage[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9+/=]{20,}[\"']"), "Похоже на Azure Storage key"),
    ("private_key_pem", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "PEM private key в JS"),
    ("openssh_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "OpenSSH private key в JS"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]+\b"), "Похоже на Slack token"),
    (
        "generic_secret",
        re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|password|bearer|token)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-+/=]{16,})[\"']"
        ),
        "Строка вида api_key/secret/token в JS",
    ),
)

_JQUERY_VER = re.compile(r"jQuery v(\d+\.\d+\.\d+)|jquery[/-](\d+\.\d+\.\d+)", re.I)
_SCRIPT_INLINE_RX = re.compile(r"<script(?![^>]+\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)


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


def extract_script_srcs(html: str, base_url: str) -> list[str]:
    urls: list[str] = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1).strip()
        if not src:
            continue
        if src.startswith("data:"):
            # data URI обрабатываем как inline-контент и не загружаем по сети
            continue
        absolute = urljoin(base_url, src)
        if absolute not in urls:
            urls.append(absolute)
    return urls


def extract_inline_script_bodies(html: str, *, max_chunks: int = 25) -> list[str]:
    chunks: list[str] = []
    for m in _SCRIPT_INLINE_RX.finditer(html):
        body = (m.group(1) or "").strip()
        if not body:
            continue
        chunks.append(body[:500000])
        if len(chunks) >= max_chunks:
            break
    return chunks


def _scan_js_blob(body: str, *, affected: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for name, rx, title in _SECRET_PATTERNS:
        hit = rx.search(body)
        if not hit:
            continue
        frag = hit.group(0)
        if len(frag) > 90:
            frag = frag[:90] + "…"
        findings.append(
            _f(
                "js-surface",
                "high" if name in {"aws_key", "private_key_pem", "openssh_key", "slack_token", "openai", "github_pat"} else "medium",
                title,
                f"Файл/блок: {affected}\nФрагмент: {frag}",
                "Уберите секреты из клиентского JS; используйте backend и переменные окружения.",
                affected,
            )
        )
        break

    jm = _JQUERY_VER.search(body)
    if jm:
        ver = jm.group(1) or jm.group(2)
        if ver:
            findings.extend(
                findings_for_version("jquery", ver)
                or [
                    _f(
                        "js-surface",
                        "info",
                        "Версия jQuery в JS",
                        ver,
                        "Проверьте актуальность и CVE.",
                        affected,
                    )
                ]
            )
    return findings


def findings_js_surface(
    html: str,
    target_url: str,
    *,
    scan_log_path: Path | None,
    rotation_start: int,
    max_scripts: int = 14,
    max_body: int = 500000,
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    idx = rotation_start

    # Встроенные скрипты — быстрый анализ без доп. сетевых запросов
    for i, body in enumerate(extract_inline_script_bodies(html), start=1):
        findings.extend(_scan_js_blob(body[:max_body], affected=f"{target_url}#inline-script-{i}"))

    scripts = extract_script_srcs(html, target_url)[:max_scripts]
    for src in scripts:
        pr = passive_probe(src, scan_log_path=scan_log_path, rotation_index=idx, max_body=max_body)
        idx += 1
        if pr.get("error") or pr.get("status_code") != 200:
            continue
        body = (pr.get("body") or "")[:max_body]
        findings.extend(_scan_js_blob(body, affected=urlparse(src).path or src))

    return findings, idx
