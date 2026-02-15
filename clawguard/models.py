"""Pydantic models for ClawGuard sanitization pipeline."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskFlagType(str, Enum):
    HTML_DETECTED = "html_detected"
    INJECTION_DETECTED = "injection_detected"
    SCRIPT_DETECTED = "script_detected"
    SECRET_DETECTED = "secret_detected"
    UNICODE_SUSPICIOUS = "unicode_suspicious"
    ATTACHMENT_BLOCKED = "attachment_blocked"
    OVERSIZED = "oversized"
    HIDDEN_CONTENT = "hidden_content"


class RiskInfo(BaseModel):
    flags: list[RiskFlagType] = Field(default_factory=list)
    injection_detected: bool = False
    truncated: bool = False
    risk_score: int = Field(default=0, ge=0, le=100)
    injection_patterns_found: list[str] = Field(default_factory=list)


class AttachmentSanitized(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    allowed: bool
    extracted_text: str | None = None
    blocked_reason: str | None = None


class OriginalSizes(BaseModel):
    subject: int = 0
    body: int = 0
    attachments_count: int = 0
    total_attachment_bytes: int = 0


class SanitizationMeta(BaseModel):
    original_sizes: OriginalSizes = Field(default_factory=OriginalSizes)
    sanitizer_version: str = "v1"
    processing_time_ms: float = 0.0
    html_stripped: bool = False
    unicode_cleaned: bool = False
    secrets_redacted: int = 0


class SanitizedEmailEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    provider: str = "generic"
    received_at: datetime = Field(default_factory=datetime.utcnow)
    from_addr: str = ""
    to_addrs: list[str] = Field(default_factory=list)
    subject_sanitized: str = ""
    body_sanitized: str = ""
    attachments_sanitized: list[AttachmentSanitized] = Field(default_factory=list)
    risk: RiskInfo = Field(default_factory=RiskInfo)
    meta: SanitizationMeta = Field(default_factory=SanitizationMeta)


class RawEmailPayload(BaseModel):
    """Inbound email webhook payload - flexible to accept various formats."""
    from_addr: str | None = Field(None, alias="from")
    from_address: str | None = None
    to: str | list[str] | None = None
    to_addrs: list[str] | None = None
    subject: str | None = None
    body: str | None = None
    body_html: str | None = None
    body_plain: str | None = None
    text: str | None = None
    html: str | None = None
    attachments: list[dict[str, Any]] | None = None
    headers: dict[str, str] | None = None
    provider: str | None = None
    timestamp: str | None = None

    class Config:
        populate_by_name = True

    def get_from(self) -> str:
        return self.from_addr or self.from_address or ""

    def get_to(self) -> list[str]:
        if self.to_addrs:
            return self.to_addrs
        if isinstance(self.to, list):
            return self.to
        if isinstance(self.to, str):
            return [self.to]
        return []

    def get_subject(self) -> str:
        return self.subject or ""

    def get_body_html(self) -> str:
        return self.body_html or self.html or ""

    def get_body_plain(self) -> str:
        return self.body_plain or self.text or self.body or ""

    def get_body(self) -> str:
        """Return the best available body content."""
        return self.get_body_html() or self.get_body_plain()

    def has_html(self) -> bool:
        return bool(self.get_body_html())


class WebhookEvent(BaseModel):
    """Generic wrapper for any inbound webhook."""
    event_type: str = "email"
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class EventRecord(BaseModel):
    """Database record for stored events."""
    id: int | None = None
    event_id: str
    provider: str
    received_at: datetime
    from_addr: str
    subject_sanitized: str
    body_sanitized: str
    risk_flags: str  # JSON string
    injection_detected: bool
    truncated: bool
    risk_score: int
    raw_payload: str | None = None  # encrypted/masked
    sanitized_json: str  # full sanitized event JSON


class DashboardStats(BaseModel):
    total_processed: int = 0
    risky_count: int = 0
    injection_count: int = 0
    attachments_blocked: int = 0
    avg_risk_score: float = 0.0
    events_today: int = 0
