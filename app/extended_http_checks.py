"""
OPTIONS (Allow), CORS — расширенные проверки без агрессивного fuzzing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.adaptive_http import passive_probe

_EVIL_ORIGIN = "https://evil-example-scanner.invalid"


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


def findings_http_options_and_cors(
    target_url: str,
    *,
    scan_log_path: Path | None,
    rotation_start: int,
    cors_paths: list[str] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    idx = rotation_start
    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    root_url = f"{origin}/"

    pr = passive_probe(
        root_url,
        method="OPTIONS",
        scan_log_path=scan_log_path,
        rotation_index=idx,
        max_body=16384,
    )
    idx += 1
    if pr.get("status_code") in (None, 404):
        pr = passive_probe(target_url, method="OPTIONS", scan_log_path=scan_log_path, rotation_index=idx)
        idx += 1

    allow = (pr.get("headers") or {}).get("allow", "")
    if allow:
        methods = {m.strip().upper() for m in re.split(r"[,\s]+", allow) if m.strip()}
        if "TRACE" in methods:
            findings.append(
                _f(
                    "passive-http",
                    "medium",
                    "HTTP OPTIONS: разрешён TRACE",
                    f"Allow: {allow[:500]}",
                    "Отключите TRACE на веб-сервере (XST / отладочные риски).",
                    target_url,
                )
            )
        if "PUT" in methods:
            findings.append(
                _f(
                    "passive-http",
                    "high",
                    "HTTP OPTIONS: разрешён PUT",
                    f"Allow: {allow[:500]}",
                    "Убедитесь, что PUT недоступен анонимно и не приводит к записи в web-root.",
                    target_url,
                )
            )
        if "DELETE" in methods:
            findings.append(
                _f(
                    "passive-http",
                    "high",
                    "HTTP OPTIONS: разрешён DELETE",
                    f"Allow: {allow[:500]}",
                    "Ограничьте DELETE; проверьте авторизацию и CSRF.",
                    target_url,
                )
            )
    elif pr.get("status_code") == 200:
        findings.append(
            _f(
                "passive-http",
                "info",
                "HTTP OPTIONS: ответ 200 без заголовка Allow",
                f"status={pr.get('status_code')}",
                "Allow не обязателен; при необходимости явно задайте разрешённые методы.",
                target_url,
            )
        )

    trace_header_name = "X-Security-Combine-Trace"
    trace_value = "trace-check-12345"
    pr_t = passive_probe(
        root_url,
        method="TRACE",
        scan_log_path=scan_log_path,
        rotation_index=idx,
        extra_headers={trace_header_name: trace_value},
        max_body=4096,
    )
    idx += 1
    if pr_t.get("status_code") == 200 and trace_value.lower() in (pr_t.get("body") or "").lower():
        findings.append(
            _f(
                "passive-http",
                "high",
                "TRACE отражает пользовательские заголовки (XST)",
                "Сервер возвращает тело TRACE с отражением входных заголовков.",
                "Отключите TRACE и ограничьте диагностические HTTP-методы.",
                target_url,
            )
        )

    cors_candidates = [target_url]
    if cors_paths:
        seen: set[str] = set(cors_candidates)
        for path in cors_paths[:5]:
            if not path:
                continue
            if path.startswith(("http://", "https://")):
                url = path
            else:
                url = origin + (path if path.startswith("/") else "/" + path)
            if url in seen:
                continue
            seen.add(url)
            cors_candidates.append(url)

    for cors_url in cors_candidates[:6]:
        pr_c = passive_probe(
            cors_url,
            method="GET",
            scan_log_path=scan_log_path,
            rotation_index=idx,
            extra_headers={"Origin": _EVIL_ORIGIN, "Access-Control-Request-Method": "GET"},
            max_body=4096,
        )
        idx += 1
        h = pr_c.get("headers") or {}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "")
        if acao == "*":
            sev = "critical" if "true" in acac.lower() else "high"
            findings.append(
                _f(
                    "passive-http",
                    sev,
                    "CORS: Access-Control-Allow-Origin: *",
                    f"URL: {cors_url}, credentials: {acac or '—'}",
                    "Не используйте * для API с cookie/токенами; задайте whitelist origin.",
                    cors_url,
                )
            )
        elif acao and _EVIL_ORIGIN in acao:
            sev = "high" if "true" in acac.lower() else "medium"
            findings.append(
                _f(
                    "passive-http",
                    sev,
                    "CORS: отражён недоверенный Origin",
                    f"URL: {cors_url}, Access-Control-Allow-Origin: {acao[:200]}, credentials: {acac or '—'}",
                    "Не отражайте произвольный Origin; whitelist только доверенных доменов.",
                    cors_url,
                )
            )

    return findings, idx
