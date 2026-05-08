from datetime import datetime
from typing import Any, Literal
import re
from urllib.parse import unquote_plus

from pydantic import BaseModel, HttpUrl, field_validator


_SQLI_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bunion\s+all?\s+select\b"),
    re.compile(r"(?i)\b(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?"),
    re.compile(r"(?i)\b(?:sleep|benchmark|pg_sleep)\s*\("),
    re.compile(r"(?i)\b(?:drop|truncate|alter)\s+table\b"),
    re.compile(r"(?i)\binformation_schema\b|\bxp_cmdshell\b"),
    re.compile(r"(?i);\s*(?:select|insert|update|delete|drop|alter)\b"),
    re.compile(r"(?i)(?:--|/\*)\s*[^\s]*"),
)


def _contains_sqli_signatures(value: str) -> bool:
    if not value:
        return False
    decoded = unquote_plus(value)
    checked = (value, decoded)
    for candidate in checked:
        for pattern in _SQLI_PATTERNS:
            if pattern.search(candidate):
                return True
    return False


class ScanRequest(BaseModel):
    url: HttpUrl
    run_external_tools: bool = True
    notes: str | None = None
    requester: str | None = None
    engagement_id: str | None = None

    @field_validator("url", mode="before")
    @classmethod
    def validate_url_no_sqli(cls, value: object) -> object:
        text = str(value or "")
        if _contains_sqli_signatures(text):
            raise ValueError("Input contains potential SQL injection patterns")
        return value

    @field_validator("notes", "requester", "engagement_id", mode="before")
    @classmethod
    def validate_text_fields_no_sqli(cls, value: object) -> object:
        if value is None:
            return None
        text = str(value)
        if _contains_sqli_signatures(text):
            raise ValueError("Input contains potential SQL injection patterns")
        return value


class ScanResult(BaseModel):
    job_id: str
    status: Literal["pending", "running", "completed", "failed", "paused"]
    started_at: datetime | None = None
    finished_at: datetime | None = None
    target_url: str
    notes: str | None = None
    requester: str | None = None
    engagement_id: str | None = None
    run_external_tools: bool = True
    error: str | None = None
    report_file: str | None = None
    summary: dict[str, Any] | None = None
    progress_step: str | None = None
    progress_current: int = 0
    progress_total: int = 0
