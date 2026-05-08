"""
Адаптивные HTTP-запросы для целей за WAF/CDN/антиботом (только с явным разрешением).
Ротация UA/заголовков и задержки снижают ложные срабатывания и нагрузку.
Челленджи и блокировки только логируются; капча не решается автоматически.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen

logger = logging.getLogger("security_combine.adaptive_http")

# Пулы для ротации (без имитации конкретных пользователей — типовые строки клиентов)
_USER_AGENTS: tuple[str, ...] = (
    os.getenv("SECURITY_COMBINE_USER_AGENT", "").strip()
    or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
)

_ACCEPT_LANGUAGE_VARIANTS: tuple[str, ...] = (
    "en-US,en;q=0.9,ru;q=0.8",
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-GB,en;q=0.9",
)

# Sec-Fetch-Site: комбинируем разные значения, чтобы не формировать один шаблон
_SEC_FETCH_SITE: tuple[str, ...] = ("none", "same-origin", "cross-site")
_LOG_SUCCESS = os.getenv("SECURITY_COMBINE_LOG_SUCCESS", "").strip().lower() in {"1", "true", "yes", "on"}


class OperatorActionRequired(Exception):
    """Цель стабильно отвечает блокировкой/челленджем — нужен оператор (ручной режим)."""

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


@dataclass
class ChallengeInfo:
    kind: str
    status_code: int
    hints: list[str] = field(default_factory=list)
    body_preview: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _adaptive_delay_before_request() -> None:
    """Случайная пауза между запросами (мс из env)."""
    lo = _env_float("SECURITY_COMBINE_ADAPTIVE_DELAY_MS_MIN", 400.0)
    hi = _env_float("SECURITY_COMBINE_ADAPTIVE_DELAY_MS_MAX", 2200.0)
    if hi < lo:
        lo, hi = hi, lo
    time.sleep(random.uniform(lo, hi) / 1000.0)


def _pipeline_step_delay() -> None:
    sec = _env_float("SECURITY_COMBINE_PIPELINE_STEP_DELAY_SEC", 1.5)
    if sec > 0:
        time.sleep(sec)


def _pool_pick(pool: tuple[str, ...], attempt_index: int) -> str:
    """
    Выбор значения из пула с псевдослучайной сменой комбинаций.
    Индекс зависит от попытки и 10-минутного слота времени.
    """
    if not pool:
        return ""
    slot = int(time.time() // 600)
    base = (slot + attempt_index + random.randrange(len(pool))) % len(pool)
    return pool[base]


def _headers_for_attempt(target_url: str, attempt_index: int) -> dict[str, str]:
    parsed = urlparse(target_url)
    site_root = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
    ua = _pool_pick(_USER_AGENTS, attempt_index)
    accept_lang = _pool_pick(_ACCEPT_LANGUAGE_VARIANTS, attempt_index)
    sec_site = _pool_pick(_SEC_FETCH_SITE, attempt_index)
    # identity — чтобы тело ответов при ошибках было текстом для детекта челленджей
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": accept_lang,
        "Accept-Encoding": "identity",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": sec_site,
        "Sec-Fetch-User": "?1",
        "Referer": site_root,
        "Cache-Control": "max-age=0",
    }


# Не немедленная пауза: можно повторить с ротацией/задержкой
_SOFT_BLOCK_KINDS = frozenset(
    {
        "http_block_unknown",
        "rate_limited",
        "service_unavailable",
        "forbidden_empty_body",
        "cdn_edge_block",
    }
)

_CHALLENGE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("cloudflare_js", re.compile(r"cf-challenge|__cf_bm|cloudflare|checking your browser|just a moment", re.I)),
    ("turnstile", re.compile(r"turnstile|challenges\.cloudflare\.com", re.I)),
    ("datadome", re.compile(r"datadome|dd_cookie", re.I)),
    ("perimeterx", re.compile(r"perimeterx|px-captcha|_px\d?", re.I)),
    ("akamai_bot", re.compile(r"akamai|ak_bmsc", re.I)),
    ("incapsula", re.compile(r"incapsula|_incapsula", re.I)),
    ("sucuri", re.compile(r"sucuri|sucuri cloudproxy", re.I)),
    ("generic_js_challenge", re.compile(r"challenge\.js|browser.?check|enable.?javascript", re.I)),
    ("captcha_marker", re.compile(r"g-recaptcha|hcaptcha|captcha|recaptcha", re.I)),
)


def _kind_is_soft(kind_value: str) -> bool:
    kinds = [x.strip() for x in kind_value.split(",") if x.strip()]
    return bool(kinds) and all(x in _SOFT_BLOCK_KINDS for x in kinds)


def _header_hints(h: dict[str, str]) -> list[str]:
    out: list[str] = []
    low = {k.lower(): v for k, v in h.items()}
    if "cf-ray" in low:
        out.append("cf-ray")
    if "x-cdn" in low:
        out.append(f"x-cdn:{low['x-cdn'][:80]}")
    if "x-cache" in low:
        out.append(f"x-cache:{low['x-cache'][:80]}")
    serv = low.get("server", "")
    if "cloudflare" in serv.lower():
        out.append("server:cloudflare")
    if "datadome" in serv.lower():
        out.append("server:datadome")
    if "akamai" in serv.lower():
        out.append("server:akamai")
    if "cloudfront" in serv.lower():
        out.append("server:cloudfront")
    if "fastly" in serv.lower():
        out.append("server:fastly")
    return out


def classify_guard_response(
    status_code: int,
    headers: dict[str, str],
    body_text: str,
) -> ChallengeInfo | None:
    """Определить, похоже ли на WAF/JS-челлендж/капчу (без решения)."""
    if status_code not in (403, 406, 429, 503):
        # 406 — «неприемлемый» клиент; 429 — rate limit; 503 — часто edge/WAF
        return None
    hints = _header_hints(headers)
    lower = body_text.lower()
    kinds: list[str] = []
    h_join = " ".join(hints).lower()
    for name, rx in _CHALLENGE_PATTERNS:
        if rx.search(lower) or rx.search(h_join):
            kinds.append(name)
    if status_code == 403 and not lower.strip():
        kinds.append("forbidden_empty_body")
    if status_code in (403, 429, 503):
        generic_markers = (
            "access denied",
            "request blocked",
            "forbidden",
            "blocked",
            "security policy",
            "incident id",
            "ray id",
            "support id",
            "temporarily unavailable",
            "too many requests",
        )
        if any(marker in lower for marker in generic_markers):
            kinds.append("waf_block_page")
        if "x-cdn:" in h_join or any(x in h_join for x in ("cloudfront", "fastly", "akamai", "cloudflare")):
            kinds.append("cdn_edge_block")
    if kinds:
        return ChallengeInfo(
            kind=",".join(dict.fromkeys(kinds)),
            status_code=status_code,
            hints=hints,
            body_preview=body_text[:4000],
            response_headers={k.lower(): v for k, v in headers.items()},
        )
    if status_code in (403, 406):
        return ChallengeInfo(
            kind="http_block_unknown",
            status_code=status_code,
            hints=hints,
            body_preview=body_text[:4000],
            response_headers={k.lower(): v for k, v in headers.items()},
        )
    if status_code == 429:
        return ChallengeInfo(
            kind="rate_limited",
            status_code=429,
            hints=hints,
            body_preview=body_text[:4000],
            response_headers={k.lower(): v for k, v in headers.items()},
        )
    if status_code == 503:
        return ChallengeInfo(
            kind="service_unavailable",
            status_code=503,
            hints=hints,
            body_preview=body_text[:4000],
            response_headers={k.lower(): v for k, v in headers.items()},
        )
    return None


def _should_write_log_record(record: dict) -> bool:
    if _LOG_SUCCESS:
        return True
    event = str(record.get("event", "")).lower()
    if event in {"http_error", "network_error", "guard", "operator_pause"}:
        return True
    status = record.get("status")
    if isinstance(status, int) and status >= 400:
        return True
    return False


def _append_scan_log(log_path: Path | None, record: dict) -> None:
    if not log_path:
        return
    if not _should_write_log_record(record):
        return
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(line)
    except OSError as exc:
        logger.warning("Не удалось записать adaptive.log: %s", exc)


def _fallback_meta_from_http_error(
    target_url: str,
    exc: HTTPError,
    body_text: str,
    *,
    attempts_used: int,
) -> dict:
    headers_low = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
    set_cookie_list: list[str] = []
    if exc.headers and hasattr(exc.headers, "get_all"):
        set_cookie_list = list(exc.headers.get_all("Set-Cookie") or [])
    elif exc.headers:
        sc = exc.headers.get("Set-Cookie")
        if sc:
            set_cookie_list = [sc]
    return {
        "status_code": exc.code,
        "headers": headers_low,
        "final_url": target_url,
        "body_preview": (body_text or "")[:65536],
        "set_cookie_list": set_cookie_list,
        "adaptive": {"attempts_used": attempts_used, "degraded": True, "fallback_http_error": exc.code},
    }


def fetch_page_meta_adaptive(
    target_url: str,
    *,
    attempts: int | None = None,
    scan_log_path: Path | None = None,
) -> dict:
    """
    GET с ротацией UA/заголовков и задержками.
    При устойчивой блокировке/challenge — OperatorActionRequired.
    """
    n_attempts = attempts if attempts is not None else int(_env_float("SECURITY_COMBINE_ADAPTIVE_ATTEMPTS", 4))
    n_attempts = max(1, min(n_attempts, 12))

    last_exc: BaseException | None = None

    for attempt in range(n_attempts):
        if attempt > 0:
            _adaptive_delay_before_request()
        headers = _headers_for_attempt(target_url, attempt)
        try:
            request = Request(target_url, headers=headers, method="GET")
            with urlopen(request, timeout=30) as response:  # noqa: S310
                h = {key.lower(): value for key, value in response.headers.items()}
                body_preview = ""
                ctype = h.get("content-type", "")
                if "text" in ctype or "html" in ctype or "json" in ctype:
                    try:
                        raw = response.read(65536)
                        body_preview = raw.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        body_preview = ""
                set_cookie_list: list[str] = []
                hdrs_raw = response.headers
                if hasattr(hdrs_raw, "get_all"):
                    set_cookie_list = list(hdrs_raw.get_all("Set-Cookie") or [])
                else:
                    sc = hdrs_raw.get("Set-Cookie")
                    if sc:
                        set_cookie_list = [sc]
                rec = {
                    "ts": time.time(),
                    "event": "success",
                    "url": target_url,
                    "attempt": attempt + 1,
                    "status": response.status,
                    "user_agent": headers["User-Agent"][:120],
                }
                _append_scan_log(scan_log_path, rec)
                if _LOG_SUCCESS:
                    logger.info(
                        "adaptive_http OK %s status=%s attempt=%s",
                        target_url,
                        response.status,
                        attempt + 1,
                    )
                return {
                    "status_code": response.status,
                    "headers": h,
                    "final_url": response.geturl(),
                    "body_preview": body_preview,
                    "set_cookie_list": set_cookie_list,
                    "adaptive": {"attempts_used": attempt + 1},
                }
        except HTTPError as exc:
            last_exc = exc
            hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            try:
                body = exc.read()
            except Exception:  # noqa: BLE001
                body = b""
            text = body.decode("utf-8", errors="replace")[:12000]
            info = classify_guard_response(exc.code, hdrs, text)
            rec = {
                "ts": time.time(),
                "event": "http_error",
                "url": target_url,
                "attempt": attempt + 1,
                "status": exc.code,
                "user_agent": headers["User-Agent"][:120],
                "challenge": None,
            }
            if info:
                rec["challenge"] = {
                    "kind": info.kind,
                    "hints": info.hints,
                    "body_preview": info.body_preview[:2000],
                }
                logger.warning(
                    "adaptive_http guard url=%s status=%s kind=%s hints=%s (попытка %s/%s; капча/JS не решаются автоматически)",
                    target_url,
                    exc.code,
                    info.kind,
                    info.hints,
                    attempt + 1,
                    n_attempts,
                )
            else:
                logger.warning(
                    "adaptive_http HTTP %s url=%s attempt=%s",
                    exc.code,
                    target_url,
                    attempt + 1,
                )
            _append_scan_log(scan_log_path, rec)

            # Явный WAF/JS/капча — сразу пауза для ручного режима (ротация UA обычно не помогает)
            if info and not _kind_is_soft(info.kind):
                raise OperatorActionRequired(
                    "Скан приостановлен: обнаружена защита (WAF/JS-челлендж или блокировка). "
                    "См. adaptive.log; при необходимости пройдите проверку вручную — автоматическое решение капчи отключено.",
                    details={
                        "status_code": exc.code,
                        "challenge_kind": info.kind,
                        "hints": info.hints,
                        "attempts": attempt + 1,
                    },
                ) from exc
            # Мягкая блокировка: повтор с ротацией; после исчерпания попыток — пауза
            if info and _kind_is_soft(info.kind):
                if attempt >= n_attempts - 1:
                    if exc.code == 503:
                        logger.warning(
                            "adaptive_http soft 503 persisted after %s attempts for %s; continuing in degraded mode",
                            n_attempts,
                            target_url,
                        )
                        return _fallback_meta_from_http_error(
                            target_url,
                            exc,
                            text,
                            attempts_used=n_attempts,
                        )
                    raise OperatorActionRequired(
                        "Скан приостановлен: цель отвечает блокировкой (HTTP "
                        f"{exc.code}) после {n_attempts} попыток с ротацией UA/заголовков. "
                        "См. adaptive.log и уточните у владельца доступ/исключения WAF.",
                        details={"status_code": exc.code, "challenge_kind": info.kind, "attempts": n_attempts},
                    ) from exc
                time.sleep(0.5 * (2**attempt))
                continue
            if exc.code in (403, 406, 429) and info is None:
                if attempt >= n_attempts - 1:
                    raise OperatorActionRequired(
                        f"Скан приостановлен: повторяющиеся ответы HTTP {exc.code} без распознанного шаблона защиты. "
                        "См. adaptive.log.",
                        details={"status_code": exc.code, "attempts": n_attempts},
                    ) from exc
                time.sleep(0.5 * (2**attempt))
                continue
            if attempt < n_attempts - 1:
                time.sleep(0.5 * (2**attempt))
                continue
            raise
        except (URLError, OSError, TimeoutError) as exc:
            last_exc = exc
            rec = {
                "ts": time.time(),
                "event": "network_error",
                "url": target_url,
                "attempt": attempt + 1,
                "error": str(exc),
            }
            _append_scan_log(scan_log_path, rec)
            logger.warning("adaptive_http network error %s: %s", target_url, exc)
            if attempt < n_attempts - 1:
                time.sleep(0.6 * (2**attempt))
                continue
            raise

    assert last_exc is not None
    raise last_exc


def passive_probe(
    full_url: str,
    *,
    method: str = "GET",
    scan_log_path: Path | None = None,
    rotation_index: int = 0,
    max_body: int = 65536,
    timeout: int = 22,
    extra_headers: dict[str, str] | None = None,
    retries: int | None = None,
    delay_first_attempt: bool = False,
) -> dict:
    """
    Один HTTP-запрос (GET/OPTIONS/HEAD/…) без OperatorActionRequired.
    """
    retries_count = retries
    if retries_count is None:
        retries_count = int(_env_float("SECURITY_COMBINE_PROBE_RETRIES", 1))
    retries_count = max(0, min(int(retries_count), 4))
    method_up = method.upper()
    last_error: str | None = None
    for attempt in range(retries_count + 1):
        if attempt > 0 or (attempt == 0 and delay_first_attempt):
            _adaptive_delay_before_request()
        headers = dict(_headers_for_attempt(full_url, rotation_index + attempt))
        if extra_headers:
            headers.update(extra_headers)
        rec: dict = {
            "ts": time.time(),
            "event": "probe",
            "method": method_up,
            "url": full_url,
            "probe_attempt": attempt + 1,
            "user_agent": headers["User-Agent"][:120],
        }
        try:
            request = Request(full_url, headers=headers, method=method_up)
            with urlopen(request, timeout=timeout) as response:  # noqa: S310
                h = {key.lower(): value for key, value in response.headers.items()}
                body = ""
                if method_up != "HEAD":
                    try:
                        raw = response.read(max_body)
                        body = raw.decode("utf-8", errors="replace")
                    except Exception:  # noqa: BLE001
                        body = ""
                rec["status"] = response.status
                _append_scan_log(scan_log_path, {**rec, "status": response.status})
                return {
                    "ok": True,
                    "status_code": response.status,
                    "headers": h,
                    "body": body,
                    "final_url": response.geturl(),
                    "error": None,
                }
        except HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:max_body]
            except Exception:  # noqa: BLE001
                body = ""
            hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            rec["status"] = exc.code
            _append_scan_log(scan_log_path, {**rec, "status": exc.code})
            return {
                "ok": False,
                "status_code": exc.code,
                "headers": hdrs,
                "body": body,
                "final_url": full_url,
                "error": None,
            }
        except (URLError, OSError, TimeoutError) as exc:
            last_error = str(exc)
            rec["event"] = "network_error"
            rec["error"] = last_error
            _append_scan_log(scan_log_path, rec)
            if attempt < retries_count:
                time.sleep(0.35 * (2**attempt))
                continue
            return {
                "ok": False,
                "status_code": None,
                "headers": {},
                "body": "",
                "final_url": full_url,
                "error": last_error,
            }
    return {
        "ok": False,
        "status_code": None,
        "headers": {},
        "body": "",
        "final_url": full_url,
        "error": last_error or "probe failed",
    }


def passive_probe_get(
    full_url: str,
    *,
    scan_log_path: Path | None = None,
    rotation_index: int = 0,
    max_body: int = 65536,
    timeout: int = 22,
) -> dict:
    return passive_probe(
        full_url,
        method="GET",
        scan_log_path=scan_log_path,
        rotation_index=rotation_index,
        max_body=max_body,
        timeout=timeout,
    )


__all__ = [
    "OperatorActionRequired",
    "ChallengeInfo",
    "classify_guard_response",
    "fetch_page_meta_adaptive",
    "passive_probe_get",
    "passive_probe",
    "_pipeline_step_delay",
]
