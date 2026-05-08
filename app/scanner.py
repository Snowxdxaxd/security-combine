import json
import ipaddress
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from app.adaptive_http import OperatorActionRequired, _pipeline_step_delay, fetch_page_meta_adaptive
from app.extended_http_checks import findings_http_options_and_cors
from app.js_leak_scan import findings_js_surface
from app.passive_analysis import (
    analyze_tls_deep,
    analyze_headers_info_leak,
    cookie_flags_findings,
    findings_banner_versions,
    findings_bitrix_version_probe,
    findings_fingerprint,
    findings_hidden_fields,
    findings_js_query_params,
    findings_open_directories,
    findings_security_headers,
    findings_sensitive_and_discovery,
    findings_seo_surface_expansion,
)
from app.reporting import render_html_report
from app.sql_audit import run_sqli_surface_audit

# (label, current, total) — этап скана для UI
ProgressCallback = Callable[[str, int, int], None]

BASE_DIR = Path(os.getenv("SECURITY_COMBINE_BASE_DIR", Path(__file__).resolve().parent.parent))
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
_DOCKER_IMAGES_READY: set[str] = set()
_DOCKER_DAEMON_READY: bool | None = None


# ---------------------------------------------------------------------------
# Новые настройки активного SQLi-аудита (добавлено)
# ---------------------------------------------------------------------------
def _is_sqli_active_enabled() -> bool:
    """Активная отправка инъекционных пейлоадов (test_injections)."""
    return os.getenv("SECURITY_COMBINE_SQLI_ACTIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def _is_sqli_extract_enabled() -> bool:
    """Извлечение данных из БД при успешной инъекции (extract_data)."""
    return os.getenv("SECURITY_COMBINE_SQLI_EXTRACT", "").strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Все остальные функции остаются без изменений, кроме отмеченных ниже
# ---------------------------------------------------------------------------

def _is_public_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        pass
    if host.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    for info in infos:
        ip_str = info[4][0]
        ip = ipaddress.ip_address(ip_str)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
    return True


def _assert_target_is_public(target_url: str) -> None:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Target URL has no hostname")
    if not _is_public_host(host):
        raise ValueError("Target URL resolves to local/private network; request blocked")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_target_url(url: str) -> str:
    u = (url or "").strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def _load_checkpoint(path: Path) -> dict:
    if not path.exists():
        return {"version": 1, "probe_cache": {}, "created_at": _now_iso()}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": 1, "probe_cache": {}, "created_at": _now_iso()}
    if not isinstance(data, dict):
        return {"version": 1, "probe_cache": {}, "created_at": _now_iso()}
    if not isinstance(data.get("probe_cache"), dict):
        data["probe_cache"] = {}
    return data


def _save_checkpoint(path: Path, checkpoint: dict) -> None:
    checkpoint["updated_at"] = _now_iso()
    path.write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")


def _run_command(command: list[str], timeout_seconds: int) -> dict:
    started_at = _now_iso()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "started_at": started_at,
            "finished_at": _now_iso(),
            "exit_code": completed.returncode,
            "stdout": completed.stdout[-12000:],
            "stderr": completed.stderr[-12000:],
            "timed_out": False,
            "skipped": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "started_at": started_at,
            "finished_at": _now_iso(),
            "exit_code": -1,
            "stdout": (exc.stdout or "")[-12000:],
            "stderr": (exc.stderr or "")[-12000:],
            "timed_out": True,
            "skipped": False,
        }


def _ensure_docker_image(image: str) -> dict | None:
    if image in _DOCKER_IMAGES_READY:
        return None
    inspect = _run_command(["docker", "image", "inspect", image], timeout_seconds=45)
    if inspect.get("exit_code") == 0:
        _DOCKER_IMAGES_READY.add(image)
        return None
    pull = _run_command(["docker", "pull", image], timeout_seconds=1200)
    if pull.get("exit_code") != 0:
        return {
            "started_at": pull["started_at"],
            "finished_at": pull["finished_at"],
            "exit_code": pull["exit_code"],
            "stdout": pull.get("stdout", ""),
            "stderr": f"Docker image pull failed for {image}. " + pull.get("stderr", ""),
            "timed_out": pull.get("timed_out", False),
            "skipped": True,
        }
    _DOCKER_IMAGES_READY.add(image)
    return None


def _docker_daemon_status() -> tuple[bool, str]:
    probe = _run_command(["docker", "info"], timeout_seconds=20)
    if probe.get("exit_code") == 0:
        return True, ""
    stderr = str(probe.get("stderr") or "").strip()
    stdout = str(probe.get("stdout") or "").strip()
    return False, stderr or stdout or "Docker daemon is not reachable"


def _try_start_docker_desktop() -> bool:
    if str(os.getenv("SECURITY_COMBINE_AUTO_START_DOCKER", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return False
    candidates = (
        os.getenv("SECURITY_COMBINE_DOCKER_DESKTOP_PATH", "").strip(),
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
        r"C:\Program Files\Docker\Docker\Docker Desktop",
    )
    for path in candidates:
        if not path:
            continue
        if not Path(path).exists():
            continue
        try:
            subprocess.Popen([path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _ensure_docker_daemon() -> dict | None:
    global _DOCKER_DAEMON_READY  # noqa: PLW0603
    if _DOCKER_DAEMON_READY is True:
        return None

    ok, err = _docker_daemon_status()
    if ok:
        _DOCKER_DAEMON_READY = True
        return None

    started = _try_start_docker_desktop()
    if started:
        for _ in range(20):
            time.sleep(3)
            ok, err = _docker_daemon_status()
            if ok:
                _DOCKER_DAEMON_READY = True
                return None

    _DOCKER_DAEMON_READY = False
    extra = " (attempted to start Docker Desktop automatically)" if started else ""
    return {
        "started_at": _now_iso(),
        "finished_at": _now_iso(),
        "exit_code": None,
        "stdout": "",
        "stderr": f"Docker daemon is unavailable{extra}. {err}",
        "timed_out": False,
        "skipped": True,
    }


def _run_or_skip(command: list[str], timeout_seconds: int, *, docker_image: str | None = None) -> dict:
    if not shutil.which("docker"):
        return {
            "started_at": _now_iso(),
            "finished_at": _now_iso(),
            "exit_code": None,
            "stdout": "",
            "stderr": "Docker CLI is not available, scanner skipped",
            "timed_out": False,
            "skipped": True,
        }
    daemon_status = _ensure_docker_daemon()
    if daemon_status:
        return daemon_status
    if docker_image:
        img_status = _ensure_docker_image(docker_image)
        if img_status:
            return img_status
    return _run_command(command, timeout_seconds)


def _make_finding(
    source: str,
    severity: str,
    title: str,
    evidence: str,
    recommendation: str,
    affected: str,
) -> dict:
    return {
        "source": source,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "affected": affected,
    }


def _run_passive_checks(
    target_url: str,
    *,
    adaptive_log_path: Path | None = None,
    checkpoint: dict | None = None,
    save_checkpoint: Callable[[dict], None] | None = None,
) -> dict:
    findings: list[dict] = []

    def _flush_partial() -> None:
        if isinstance(checkpoint, dict):
            checkpoint["last_findings"] = findings
            if save_checkpoint:
                save_checkpoint(checkpoint)

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme.lower()

    response_meta = None
    if isinstance(checkpoint, dict):
        cached = checkpoint.get("response_meta")
        if isinstance(cached, dict) and cached.get("status_code"):
            response_meta = cached
    if response_meta is None:
        try:
            response_meta = fetch_page_meta_adaptive(target_url, scan_log_path=adaptive_log_path)
        except OperatorActionRequired as exc:
            details = dict(exc.details or {})
            if isinstance(checkpoint, dict):
                details["findings"] = checkpoint.get("last_findings", [])
                details["passive_checks"] = checkpoint.get("response_meta", {})
            raise OperatorActionRequired(str(exc), details=details) from exc
        if isinstance(checkpoint, dict):
            checkpoint["response_meta"] = response_meta
            if save_checkpoint:
                save_checkpoint(checkpoint)

    html = response_meta.get("body_preview") or ""
    set_cookie_list: list[str] = list(response_meta.get("set_cookie_list") or [])

    findings.extend(findings_security_headers(response_meta["headers"], target_url))

    fp_findings, fp_meta = findings_fingerprint(
        response_meta["headers"],
        html,
        set_cookie_list,
        target_url,
    )
    findings.extend(fp_findings)
    findings.extend(cookie_flags_findings(set_cookie_list, target_url))
    findings.extend(findings_banner_versions(response_meta["headers"], target_url))
    findings.extend(analyze_headers_info_leak(response_meta["headers"], target_url))
    findings.extend(findings_hidden_fields(html, target_url))
    findings.extend(findings_js_query_params(html, target_url))
    _flush_partial()

    adaptive_attempts = (response_meta.get("adaptive") or {}).get("attempts_used") or 0
    ridx = int(adaptive_attempts)

    sens_findings, probes_sensitive, seo_ctx, ridx = findings_sensitive_and_discovery(
        target_url,
        scan_log_path=adaptive_log_path,
        rotation_start=ridx,
        checkpoint=checkpoint,
        save_checkpoint=save_checkpoint,
    )
    findings.extend(sens_findings)
    _flush_partial()

    dir_findings, probes_dirs, ridx = findings_open_directories(
        target_url,
        scan_log_path=adaptive_log_path,
        rotation_start=ridx,
        checkpoint=checkpoint,
        save_checkpoint=save_checkpoint,
    )
    findings.extend(dir_findings)
    _flush_partial()

    exp_findings, probes_seo, ridx = findings_seo_surface_expansion(
        target_url,
        seo_ctx.get("robots_txt"),
        seo_ctx.get("sitemap_xml"),
        scan_log_path=adaptive_log_path,
        rotation_start=ridx,
        checkpoint=checkpoint,
        save_checkpoint=save_checkpoint,
    )
    findings.extend(exp_findings)
    if seo_ctx.get("interrupted"):
        err_list = seo_ctx.get("errors") or []
        err_txt = "; ".join(str(x) for x in err_list[:3]) if isinstance(err_list, list) else "see adaptive.log"
        findings.append(
            _make_finding(
                source="passive-probe",
                severity="low",
                title="Пассивные пробы завершены с частичными ошибками",
                evidence=err_txt,
                recommendation="Проверьте сеть/доступ и повторите скан; уже собранные результаты сохранены.",
                affected=target_url,
            )
        )
    _flush_partial()

    if "bitrix" in (fp_meta.get("technology_tags") or {}):
        bx_f, ridx = findings_bitrix_version_probe(
            target_url,
            scan_log_path=adaptive_log_path,
            rotation_start=ridx,
            checkpoint=checkpoint,
            save_checkpoint=save_checkpoint,
        )
        findings.extend(bx_f)
        _flush_partial()

    opt_findings, ridx = findings_http_options_and_cors(
        target_url,
        scan_log_path=adaptive_log_path,
        rotation_start=ridx,
        cors_paths=[str(item.get("path", "")) for item in probes_seo[:5]],
    )
    findings.extend(opt_findings)
    _flush_partial()

    js_f, ridx = findings_js_surface(
        html,
        target_url,
        scan_log_path=adaptive_log_path,
        rotation_start=ridx,
    )
    findings.extend(js_f)
    _flush_partial()

    tls_meta: dict = {}
    if scheme == "https" and host:
        tls_findings, tls_meta = analyze_tls_deep(host, 443)
        findings.extend(tls_findings)
        _flush_partial()

    all_probes = probes_sensitive + probes_dirs + probes_seo
    response_meta["passive_extras"] = {
        "fingerprint": fp_meta,
        "probes": all_probes,
        "seo": {"robots_parsed": bool(seo_ctx.get("robots_txt")), "sitemap_parsed": bool(seo_ctx.get("sitemap_xml"))},
        "tls": tls_meta,
    }

    bp = response_meta.get("body_preview")
    if isinstance(bp, str) and len(bp) > 32000:
        response_meta["body_preview"] = bp[:32000] + "…[truncated]"

    if isinstance(checkpoint, dict):
        checkpoint["last_findings"] = findings
        checkpoint["response_meta"] = response_meta
        if save_checkpoint:
            save_checkpoint(checkpoint)

    return {"response": response_meta, "findings": findings}


# ---------------------------------------------------------------------------
# ИЗМЕНЁННАЯ ФУНКЦИЯ: теперь передаёт параметры активного аудита
# ---------------------------------------------------------------------------
def _run_sql_audit_stage(
    target_url: str,
    passive_checks: dict,
    *,
    checkpoint: dict | None = None,
    save_checkpoint: Callable[[dict], None] | None = None,
) -> dict:
    response_meta = passive_checks.get("response")
    if not isinstance(response_meta, dict):
        return passive_checks

    # Чтение настроек активного режима из переменных окружения
    test_injections = _is_sqli_active_enabled()
    extract_data = _is_sqli_extract_enabled()

    if test_injections:
        # Предупреждение в лог – активный режим включён
        import logging
        logging.getLogger("security_combine.scanner").warning(
            "Активный SQLi-аудит включён (SECURITY_COMBINE_SQLI_ACTIVE=true). "
            "Будут отправляться инъекционные пейлоады."
        )

    sql_findings, sql_meta = run_sqli_surface_audit(
        target_url,
        response_meta,
        checkpoint=checkpoint,
        save_checkpoint=save_checkpoint,
        test_injections=test_injections,
        extract_data=extract_data,
    )
    findings = passive_checks.setdefault("findings", [])
    if isinstance(findings, list):
        findings.extend(sql_findings)

    extras = response_meta.setdefault("passive_extras", {})
    if isinstance(extras, dict):
        extras["sql_audit"] = sql_meta

    if isinstance(checkpoint, dict):
        checkpoint["last_findings"] = passive_checks.get("findings", [])
        checkpoint["response_meta"] = response_meta
        if save_checkpoint:
            save_checkpoint(checkpoint)
    return passive_checks


# ---------------------------------------------------------------------------
# Все остальные функции (включая run_pipeline) без изменений
# ---------------------------------------------------------------------------

def _load_zap_findings(path: Path, target_url: str) -> list[dict]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    findings: list[dict] = []
    if isinstance(payload, list):
        sites = payload
    elif isinstance(payload, dict):
        sites = payload.get("site", [])
        if not isinstance(sites, list):
            sites = []
    else:
        return findings
    for item in sites:
        if not isinstance(item, dict):
            continue
        for alert in item.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            risk = str(alert.get("riskcode", "0"))
            severity = {"3": "high", "2": "medium", "1": "low"}.get(risk, "info")
            findings.append(
                _make_finding(
                    source="zap",
                    severity=severity,
                    title=alert.get("name", "ZAP alert"),
                    evidence=alert.get("desc", "No details"),
                    recommendation=alert.get("solution", "Review and mitigate according to alert guidance."),
                    affected=alert.get("url", target_url),
                )
            )
    return findings


def _nuclei_record_to_finding(item: object) -> dict | None:
    if not isinstance(item, dict):
        return None
    info = item.get("info", {})
    if not isinstance(info, dict):
        info = {}
    return _make_finding(
        source="nuclei",
        severity=str(info.get("severity", "info")).lower(),
        title=info.get("name", item.get("template-id", "Nuclei finding")),
        evidence=str(item.get("matcher-name", "Template matched against target")),
        recommendation="Review matched template and patch affected component.",
        affected=str(item.get("matched-at", item.get("host", ""))),
    )


def _load_nuclei_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    findings: list[dict] = []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = None

    if payload is not None:
        if isinstance(payload, list):
            for el in payload:
                finding = _nuclei_record_to_finding(el)
                if finding is not None:
                    findings.append(finding)
            return findings
        if isinstance(payload, dict):
            finding = _nuclei_record_to_finding(payload)
            if finding is not None:
                findings.append(finding)
            return findings

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, list):
            for el in item:
                finding = _nuclei_record_to_finding(el)
                if finding is not None:
                    findings.append(finding)
        else:
            finding = _nuclei_record_to_finding(item)
            if finding is not None:
                findings.append(finding)
    return findings


def _merge_nuclei_findings(paths: list[Path]) -> list[dict]:
    seen: set[tuple[str | None, str | None]] = set()
    out: list[dict] = []
    for path in paths:
        if not path.exists():
            continue
        for f in _load_nuclei_findings(path):
            key = (f.get("title"), f.get("affected"))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    return out


def _extract_lighthouse_summary(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    categories = payload.get("categories", {}) if isinstance(payload, dict) else {}
    out: dict[str, int] = {}
    if not isinstance(categories, dict):
        return out
    for key in ("performance", "accessibility", "best-practices", "seo", "pwa"):
        cat = categories.get(key)
        if isinstance(cat, dict):
            score = cat.get("score")
            if isinstance(score, (int, float)):
                out[key] = max(0, min(100, int(round(score * 100))))
    return out


def _score_severity(findings: list[dict]) -> dict:
    score = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        severity = str(item.get("severity", "info")).lower()
        score[severity if severity in score else "info"] += 1
    return score


def _score_sources(findings: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in findings:
        source = str(item.get("source", "unknown")).strip() or "unknown"
        out[source] = out.get(source, 0) + 1
    return out


def run_pipeline(
    target_url: str,
    scan_id: str,
    run_external_tools: bool = True,
    on_progress: ProgressCallback | None = None,
) -> dict:
    def _p(label: str, current: int, total: int) -> None:
        if on_progress:
            on_progress(label, current, total)

    target_url = _normalize_target_url(target_url)
    _assert_target_is_public(target_url)

    scan_dir = REPORTS_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    zap_file = scan_dir / "zap.json"
    nuclei_file = scan_dir / "nuclei.json"
    nuclei_cms_file = scan_dir / "nuclei_cms.json"
    lighthouse_file = scan_dir / "lighthouse.json"
    summary_file = scan_dir / "summary.json"
    html_path = scan_dir / "report.html"
    checkpoint_file = scan_dir / "passive_checkpoint.json"
    checkpoint = _load_checkpoint(checkpoint_file)

    def save_checkpoint_cb(data: dict) -> None:
        _save_checkpoint(checkpoint_file, data)

    checkpoint["run_count"] = int(checkpoint.get("run_count", 0) or 0) + 1
    history = checkpoint.get("run_history")
    if not isinstance(history, list):
        history = []
    history.append(_now_iso())
    checkpoint["run_history"] = history[-20:]
    save_checkpoint_cb(checkpoint)

    tool_results: dict = {"zap_baseline": None, "nuclei_cms": None, "nuclei": None, "lighthouse": None}
    adaptive_log = scan_dir / "adaptive.log"

    if run_external_tools:
        _p("Пассивные проверки (HTTP, TLS)…", 1, 6)
        try:
            passive_checks = _run_passive_checks(
                target_url,
                adaptive_log_path=adaptive_log,
                checkpoint=checkpoint,
                save_checkpoint=save_checkpoint_cb,
            )
        except OperatorActionRequired as exc:
            paused_details = dict(exc.details or {})
            partial_findings = paused_details.get("findings", [])
            if not isinstance(partial_findings, list):
                partial_findings = []
            partial_report = {
                "scan_id": scan_id,
                "target_url": target_url,
                "generated_at": _now_iso(),
                "status": "paused",
                "risk_overview": _score_severity(partial_findings),
                "source_overview": _score_sources(partial_findings),
                "findings": partial_findings,
                "passive_checks": paused_details.get("passive_checks", {}),
                "results": tool_results,
                "artifacts": {
                    "summary_json": str(summary_file),
                    "html_report": str(html_path),
                    "adaptive_log": str(adaptive_log),
                    "zap_json": str(zap_file),
                    "nuclei_json": str(nuclei_file),
                    "nuclei_cms_json": str(nuclei_cms_file),
                    "lighthouse_json": str(lighthouse_file),
                    "passive_checkpoint": str(checkpoint_file),
                },
            }
            summary_file.write_text(json.dumps(partial_report, indent=2), encoding="utf-8")
            html_path.write_text(render_html_report(partial_report), encoding="utf-8")
            checkpoint["interrupted"] = True
            checkpoint["last_findings"] = partial_findings
            checkpoint["response_meta"] = partial_report.get("passive_checks", {})
            save_checkpoint_cb(checkpoint)
            paused_details["partial_report_file"] = str(summary_file)
            paused_details["partial_summary"] = partial_report["risk_overview"]
            raise OperatorActionRequired(str(exc), details=paused_details) from exc
        _pipeline_step_delay()

        _p("Аудит SQLi поверхности…", 2, 6)
        passive_checks = _run_sql_audit_stage(
            target_url,
            passive_checks,
            checkpoint=checkpoint,
            save_checkpoint=save_checkpoint_cb,
        )
        _pipeline_step_delay()

        _p("OWASP ZAP Baseline (Docker)…", 3, 6)
        tool_results["zap_baseline"] = _run_or_skip(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{scan_dir.resolve()}:/zap/wrk:rw",
                "-v",
                f"{REPORTS_DIR.resolve()}:/reports",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t",
                target_url,
                "-J",
                "/zap/wrk/zap.json",
                "-m",
                "5",
            ],
            timeout_seconds=1200,
            docker_image="ghcr.io/zaproxy/zaproxy:stable",
        )
        _pipeline_step_delay()

        cms_tags = (
            (passive_checks["response"].get("passive_extras") or {})
            .get("fingerprint", {})
            .get("nuclei_cms_tags")
            or []
        )
        run_general_with_cms = os.getenv("SECURITY_COMBINE_NUCLEI_GENERAL_WITH_CMS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

        _p("Nuclei (Docker)…", 4, 6)
        if cms_tags:
            tool_results["nuclei_cms"] = _run_or_skip(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{REPORTS_DIR.resolve()}:/reports",
                    "projectdiscovery/nuclei:latest",
                    "-u",
                    target_url,
                    "-tags",
                    ",".join(cms_tags),
                    "-json-export",
                    f"/reports/{scan_id}/nuclei_cms.json",
                    "-rate-limit",
                    "30",
                ],
                timeout_seconds=600,
                docker_image="projectdiscovery/nuclei:latest",
            )
            _pipeline_step_delay()
        else:
            tool_results["nuclei_cms"] = {
                "started_at": _now_iso(),
                "finished_at": _now_iso(),
                "exit_code": None,
                "stdout": "",
                "stderr": "CMS tags not detected; CMS-focused nuclei scan skipped",
                "timed_out": False,
                "skipped": True,
            }

        if cms_tags and not run_general_with_cms:
            tool_results["nuclei"] = {
                "started_at": _now_iso(),
                "finished_at": _now_iso(),
                "exit_code": None,
                "stdout": "",
                "stderr": "General nuclei skipped because CMS tags were detected",
                "timed_out": False,
                "skipped": True,
            }
        else:
            tool_results["nuclei"] = _run_or_skip(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{REPORTS_DIR.resolve()}:/reports",
                    "projectdiscovery/nuclei:latest",
                    "-u",
                    target_url,
                    "-json-export",
                    f"/reports/{scan_id}/nuclei.json",
                    "-stats",
                ],
                timeout_seconds=1200,
                docker_image="projectdiscovery/nuclei:latest",
            )
            _pipeline_step_delay()

        _p("Lighthouse (Docker)…", 5, 6)
        tool_results["lighthouse"] = _run_or_skip(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{REPORTS_DIR.resolve()}:/reports",
                "femtopixel/google-lighthouse",
                target_url,
                "--output=json",
                "--output-path",
                f"/reports/{scan_id}/lighthouse.json",
                "--chrome-flags=--headless --no-sandbox",
            ],
            timeout_seconds=900,
            docker_image="femtopixel/google-lighthouse",
        )
    else:
        _p("Пассивные проверки (HTTP, TLS)…", 1, 3)
        passive_checks = _run_passive_checks(
            target_url,
            adaptive_log_path=adaptive_log,
            checkpoint=checkpoint,
            save_checkpoint=save_checkpoint_cb,
        )
        _p("Аудит SQLi поверхности…", 2, 3)
        passive_checks = _run_sql_audit_stage(
            target_url,
            passive_checks,
            checkpoint=checkpoint,
            save_checkpoint=save_checkpoint_cb,
        )
        for key in ("zap_baseline", "nuclei_cms", "nuclei", "lighthouse"):
            tool_results[key] = {
                "started_at": _now_iso(),
                "finished_at": _now_iso(),
                "exit_code": None,
                "stdout": "",
                "stderr": "External scanners disabled for this run",
                "timed_out": False,
                "skipped": True,
            }

    if run_external_tools:
        _p("Сборка отчёта…", 6, 6)
    else:
        _p("Сборка отчёта…", 3, 3)

    findings = list(passive_checks["findings"])
    findings.extend(_load_zap_findings(zap_file, target_url))
    findings.extend(_merge_nuclei_findings([nuclei_cms_file, nuclei_file]))
    lighthouse_summary = _extract_lighthouse_summary(lighthouse_file)
    if lighthouse_summary and isinstance(tool_results.get("lighthouse"), dict):
        tool_results["lighthouse"]["score_summary"] = lighthouse_summary

    report = {
        "scan_id": scan_id,
        "target_url": target_url,
        "generated_at": _now_iso(),
        "risk_overview": _score_severity(findings),
        "source_overview": _score_sources(findings),
        "findings": findings,
        "passive_checks": passive_checks["response"],
        "lighthouse_summary": lighthouse_summary,
        "results": tool_results,
        "artifacts": {
            "summary_json": str(summary_file),
            "html_report": str(html_path),
            "adaptive_log": str(adaptive_log),
            "zap_json": str(zap_file),
            "nuclei_json": str(nuclei_file),
            "nuclei_cms_json": str(nuclei_cms_file),
            "lighthouse_json": str(lighthouse_file),
            "passive_checkpoint": str(checkpoint_file),
        },
    }

    summary_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    html_path.write_text(render_html_report(report), encoding="utf-8")
    checkpoint["completed"] = True
    checkpoint["final_report_file"] = str(summary_file)
    save_checkpoint_cb(checkpoint)
    return {
        "report_file": str(summary_file),
        "summary": report["risk_overview"],
        "artifact_dir": str(scan_dir),
    }