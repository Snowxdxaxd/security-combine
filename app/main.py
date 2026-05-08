import json
import ipaddress
import logging
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.adaptive_http import OperatorActionRequired
from app.cve_catalog import initialize_nvd_cache
from app.models import ScanRequest, ScanResult
from app.scanner import run_pipeline


app = FastAPI(title="Security Combine", version="1.1.0")
BASE_DIR = Path(os.getenv("SECURITY_COMBINE_BASE_DIR", Path(__file__).resolve().parent.parent))
STATIC_DIR = BASE_DIR / "app" / "static"
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
JOBS_STATE_FILE = REPORTS_DIR / "jobs_state.json"
app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")

jobs: dict[str, ScanResult] = {}
jobs_lock = Lock()
JOB_QUEUE_MAX = max(1, int(os.getenv("SECURITY_COMBINE_JOB_QUEUE_MAX", "50")))
API_KEY = os.getenv("SECURITY_COMBINE_API_KEY", "").strip()
job_queue: Queue[str] = Queue(maxsize=JOB_QUEUE_MAX)
stop_event = Event()
worker_thread: Thread | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not API_KEY:
        return
    if x_api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


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
        ip = ipaddress.ip_address(info[4][0])
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


def _validate_public_target_url(target_url: str) -> None:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    if not host:
        raise HTTPException(status_code=422, detail="Invalid target URL")
    if not _is_public_host(host):
        raise HTTPException(
            status_code=400,
            detail="Target URL resolves to private/local network and is blocked",
        )


def _save_jobs_state() -> None:
    data = {"jobs": {job_id: job.model_dump(mode="json") for job_id, job in jobs.items()}}
    JOBS_STATE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_jobs_state() -> None:
    if not JOBS_STATE_FILE.exists():
        return
    try:
        payload = json.loads(JOBS_STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    loaded: dict[str, ScanResult] = {}
    for job_id, raw in payload.get("jobs", {}).items():
        try:
            loaded[job_id] = ScanResult(**raw)
        except Exception:  # noqa: BLE001
            continue
    jobs.update(loaded)


def _run_job(job_id: str) -> None:
    with jobs_lock:
        job = jobs[job_id]
        job.status = "running"
        job.started_at = _now()
        job.progress_step = "Запуск…"
        job.progress_current = 0
        job.progress_total = 5 if job.run_external_tools else 2
        _save_jobs_state()

    def report_progress(label: str, current: int, total: int) -> None:
        with jobs_lock:
            j = jobs.get(job_id)
            if not j:
                return
            j.progress_step = label
            j.progress_current = current
            j.progress_total = total
            _save_jobs_state()

    try:
        result = run_pipeline(
            job.target_url,
            job_id,
            run_external_tools=job.run_external_tools,
            on_progress=report_progress,
        )
        with jobs_lock:
            job = jobs[job_id]
            job.status = "completed"
            job.report_file = result["report_file"]
            job.summary = result["summary"]
            job.finished_at = _now()
            job.progress_step = "Готово"
            if job.progress_total:
                job.progress_current = job.progress_total
            _save_jobs_state()
    except OperatorActionRequired as exc:
        with jobs_lock:
            job = jobs[job_id]
            job.status = "paused"
            job.error = str(exc)
            details = exc.details if isinstance(exc.details, dict) else {}
            if isinstance(details.get("partial_summary"), dict):
                job.summary = details["partial_summary"]
            partial_report = details.get("partial_report_file")
            if isinstance(partial_report, str) and partial_report:
                job.report_file = partial_report
            job.finished_at = _now()
            if job.progress_total:
                job.progress_step = "Ожидание оператора (WAF/челлендж)"
            _save_jobs_state()
    except Exception as exc:  # noqa: BLE001
        with jobs_lock:
            job = jobs[job_id]
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = _now()
            _save_jobs_state()


def _worker_loop() -> None:
    while not stop_event.is_set():
        try:
            job_id = job_queue.get(timeout=1)
        except Empty:
            continue
        try:
            _run_job(job_id)
        finally:
            job_queue.task_done()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "queued_jobs": str(job_queue.qsize())}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/scan")
def start_scan(request: ScanRequest, _: None = Depends(_require_api_key)) -> dict[str, str]:
    _validate_public_target_url(str(request.url))
    if job_queue.full():
        raise HTTPException(status_code=429, detail="Scan queue is full; try again later")
    job_id = str(uuid4())
    with jobs_lock:
        jobs[job_id] = ScanResult(
            job_id=job_id,
            status="pending",
            target_url=str(request.url),
            notes=request.notes.strip() if request.notes else None,
            requester=request.requester.strip() if request.requester else None,
            engagement_id=request.engagement_id.strip() if request.engagement_id else None,
            run_external_tools=request.run_external_tools,
        )
        _save_jobs_state()
    try:
        job_queue.put_nowait(job_id)
    except Full as exc:
        with jobs_lock:
            jobs.pop(job_id, None)
            _save_jobs_state()
        raise HTTPException(status_code=429, detail="Scan queue is full; try again later") from exc
    return {"job_id": job_id, "status": "pending"}


@app.get("/jobs")
def list_jobs(limit: int = 100, _: None = Depends(_require_api_key)) -> list[dict]:
    bounded_limit = min(max(limit, 1), 500)
    with jobs_lock:
        items = [{"job_id": job_id, **job.model_dump(mode="json")} for job_id, job in jobs.items()]
    items.sort(
        key=lambda item: item.get("started_at") or item.get("finished_at") or item.get("job_id") or "",
        reverse=True,
    )
    return items[:bounded_limit]


@app.get("/jobs/{job_id}", response_model=ScanResult)
def get_job(job_id: str, _: None = Depends(_require_api_key)) -> ScanResult:
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        return job


@app.post("/jobs/{job_id}/resume")
def resume_job(job_id: str, _: None = Depends(_require_api_key)) -> dict[str, str]:
    if job_queue.full():
        raise HTTPException(status_code=429, detail="Scan queue is full; try again later")
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status not in {"paused", "failed"}:
            raise HTTPException(status_code=409, detail="Only paused/failed jobs can be resumed")
        job.status = "pending"
        job.error = None
        job.finished_at = None
        job.progress_current = 0
        if job.progress_total:
            job.progress_step = "Повторный запуск по запросу оператора"
        _save_jobs_state()
    try:
        job_queue.put_nowait(job_id)
    except Full as exc:
        raise HTTPException(status_code=429, detail="Scan queue is full; try again later") from exc
    return {"job_id": job_id, "status": "pending"}


@app.get("/jobs/{job_id}/report")
def get_job_report(job_id: str, _: None = Depends(_require_api_key)) -> FileResponse:
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status not in {"completed", "paused"} or not job.report_file:
            raise HTTPException(status_code=409, detail="Report is not ready yet")
        report_file = Path(job.report_file)

    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Report file does not exist")

    return FileResponse(report_file, media_type="application/json", filename=f"{job_id}-summary.json")


@app.get("/jobs/{job_id}/report/html")
def get_job_report_html(job_id: str, _: None = Depends(_require_api_key)) -> FileResponse:
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        if job.status not in {"completed", "paused"} or not job.report_file:
            raise HTTPException(status_code=409, detail="Report is not ready yet")
        report_file = Path(job.report_file)

    html_path = report_file.parent / "report.html"
    if not html_path.exists():
        raise HTTPException(
            status_code=404,
            detail="HTML report is missing; re-run the scan to regenerate",
        )
    return FileResponse(
        html_path,
        media_type="text/html; charset=utf-8",
        filename=f"{job_id}-report.html",
    )


@app.on_event("startup")
def on_startup() -> None:
    global worker_thread  # noqa: PLW0603
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        initialize_nvd_cache()
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("security_combine.main").warning("NVD cache init failed: %s", exc)
    with jobs_lock:
        _load_jobs_state()
        for job in jobs.values():
            if job.status in {"pending", "running"}:
                job.status = "failed"
                job.error = "Job was interrupted by service restart"
                job.finished_at = _now()
        _save_jobs_state()
    worker_thread = Thread(target=_worker_loop, daemon=True)
    worker_thread.start()


@app.on_event("shutdown")
def on_shutdown() -> None:
    stop_event.set()
    if worker_thread and worker_thread.is_alive():
        worker_thread.join(timeout=3)
