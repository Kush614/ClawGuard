"""Core sanitization pipeline for ClawGuard.

This module implements deterministic, regex-based sanitization to strip
dangerous content before it ever reaches an LLM agent.
"""

from __future__ import annotations

import html
import re
import time
import unicodedata
from datetime import datetime
from typing import Any

import bleach

from .models import (
    AttachmentSanitized,
    OriginalSizes,
    RawEmailPayload,
    RiskFlagType,
    RiskInfo,
    SanitizationMeta,
    SanitizedEmailEvent,
)

# --- Constants ---

MAX_SUBJECT_LENGTH = 500
MAX_BODY_LENGTH = 50_000
SANITIZER_VERSION = "v1"

ALLOWED_ATTACHMENT_TYPES = {
    "text/plain",
    "text/csv",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
}

MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB

# --- Injection Patterns ---

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|context)",
        re.IGNORECASE,
    )),
    ("new_instructions", re.compile(
        r"(new|updated?|revised?|override)\s+(instructions?|system\s*prompt|directives?)",
        re.IGNORECASE,
    )),
    ("system_prompt_override", re.compile(
        r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|from\s+now\s+on\s+you)",
        re.IGNORECASE,
    )),
    ("delimiter_injection", re.compile(
        r"(```\s*system|<\|im_start\|>|<\|system\|>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<\|endoftext\|>)",
        re.IGNORECASE,
    )),
    ("tool_call_injection", re.compile(
        r"(call\s+the\s+(function|tool)|execute\s+(function|tool|command)|run\s+(this\s+)?(command|code|script))",
        re.IGNORECASE,
    )),
    ("exfiltration_attempt", re.compile(
        r"(send\s+(this|the|all|my)\s+(to|via)|forward\s+(to|this)|leak|exfiltrate|extract\s+(and\s+send|secrets?|keys?|tokens?))",
        re.IGNORECASE,
    )),
    ("secret_request", re.compile(
        r"(reveal|show|display|print|output|tell\s+me)\s+(your\s+)?(system\s*prompt|instructions?|api\s*key|secret|password|token|credentials?)",
        re.IGNORECASE,
    )),
    ("jailbreak_attempt", re.compile(
        r"(DAN|do\s+anything\s+now|developer\s+mode|sudo\s+mode|god\s+mode|unrestricted\s+mode|bypass\s+(safety|filter|restriction))",
        re.IGNORECASE,
    )),
    ("encoding_evasion", re.compile(
        r"(base64|rot13|hex\s*encode|url\s*encode|encode\s+this)\s*(decode|the\s+following|:|this)",
        re.IGNORECASE,
    )),
    ("hidden_instruction", re.compile(
        r"(invisible\s+text|hidden\s+instruction|white\s+text|font.size.\s*0|display.\s*none)",
        re.IGNORECASE,
    )),
    ("markdown_injection", re.compile(
        r"!\[.*?\]\(https?://[^\)]*\?(q|query|prompt|instruction|cmd)=",
        re.IGNORECASE,
    )),
]

# --- Secret Patterns ---

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("api_key", re.compile(r"(sk-[a-zA-Z0-9]{20,}|api[_-]?key\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,})", re.IGNORECASE)),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("generic_secret", re.compile(r"(password|passwd|secret|token)\s*[:=]\s*['\"]?[^\s'\"]{8,}", re.IGNORECASE)),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
]

# --- Zero-width and control characters ---

ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufff9-\ufffb]"
)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


# --- HTML Patterns ---

HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
STYLE_RE = re.compile(r"<style[^>]*>.*?</style>", re.DOTALL | re.IGNORECASE)
SCRIPT_RE = re.compile(r"<script[^>]*>.*?</script>", re.DOTALL | re.IGNORECASE)
HIDDEN_ELEMENT_RE = re.compile(
    r'<[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|height\s*:\s*0|width\s*:\s*0)[^>]*>.*?</[^>]+>',
    re.DOTALL | re.IGNORECASE,
)


def strip_html(text: str) -> tuple[str, bool]:
    """Remove all HTML, scripts, styles, comments. Returns (cleaned, had_html)."""
    if not text:
        return text, False

    has_html = bool(re.search(r"<[a-zA-Z][^>]*>", text))
    if not has_html:
        return text, False

    # Remove hidden elements first (before stripping tags)
    cleaned = HIDDEN_ELEMENT_RE.sub(" [HIDDEN_CONTENT_REMOVED] ", text)
    # Remove scripts and styles
    cleaned = SCRIPT_RE.sub(" [SCRIPT_REMOVED] ", cleaned)
    cleaned = STYLE_RE.sub(" [STYLE_REMOVED] ", cleaned)
    # Remove HTML comments
    cleaned = HTML_COMMENT_RE.sub("", cleaned)
    # Strip remaining HTML tags but keep text content
    cleaned = bleach.clean(cleaned, tags=set(), strip=True)
    # Decode HTML entities
    cleaned = html.unescape(cleaned)
    # Normalize whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    return cleaned, True


def clean_unicode(text: str) -> tuple[str, bool]:
    """Remove zero-width and control characters. Returns (cleaned, had_suspicious)."""
    if not text:
        return text, False

    had_zero_width = bool(ZERO_WIDTH_CHARS.search(text))
    had_control = bool(CONTROL_CHARS.search(text))

    cleaned = ZERO_WIDTH_CHARS.sub("", text)
    cleaned = CONTROL_CHARS.sub("", cleaned)
    # Normalize unicode (NFC form)
    cleaned = unicodedata.normalize("NFC", cleaned)

    return cleaned, had_zero_width or had_control


def detect_injections(text: str) -> list[str]:
    """Detect prompt injection patterns. Returns list of pattern names found."""
    if not text:
        return []

    found = []
    for name, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            found.append(name)
    return found


def redact_injections(text: str) -> tuple[str, list[str]]:
    """Detect AND redact prompt injection patterns from text.

    Returns (redacted_text, list_of_pattern_names_found).
    """
    if not text:
        return text, []

    found = []
    for name, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            found.append(name)
            text = pattern.sub(f"[INJECTION_REDACTED:{name}]", text)
    return text, found


def redact_secrets(text: str) -> tuple[str, int]:
    """Redact detected secrets. Returns (redacted_text, count)."""
    if not text:
        return text, 0

    count = 0
    for name, pattern in SECRET_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            count += len(matches)
            text = pattern.sub(f"[SECRET_REDACTED:{name}]", text)

    return text, count


def truncate(text: str, max_length: int) -> tuple[str, bool]:
    """Truncate text to max_length. Returns (text, was_truncated)."""
    if len(text) <= max_length:
        return text, False
    return text[:max_length] + " [TRUNCATED]", True


def sanitize_attachment(attachment: dict[str, Any]) -> AttachmentSanitized:
    """Sanitize a single attachment entry."""
    filename = str(attachment.get("filename", attachment.get("name", "unknown")))
    content_type = str(attachment.get("content_type", attachment.get("type", "application/octet-stream")))
    size = int(attachment.get("size", attachment.get("size_bytes", 0)))

    if content_type not in ALLOWED_ATTACHMENT_TYPES:
        return AttachmentSanitized(
            filename=filename,
            content_type=content_type,
            size_bytes=size,
            allowed=False,
            blocked_reason=f"Content type '{content_type}' not in allowlist",
        )

    if size > MAX_ATTACHMENT_SIZE:
        return AttachmentSanitized(
            filename=filename,
            content_type=content_type,
            size_bytes=size,
            allowed=False,
            blocked_reason=f"Size {size} exceeds max {MAX_ATTACHMENT_SIZE}",
        )

    # Extract text content if available and it's a text type
    extracted_text = None
    if content_type.startswith("text/"):
        raw_text = attachment.get("content", attachment.get("data", ""))
        if isinstance(raw_text, str) and raw_text:
            cleaned, _ = strip_html(raw_text)
            cleaned, _ = clean_unicode(cleaned)
            cleaned, _ = truncate(cleaned, MAX_BODY_LENGTH)
            extracted_text = cleaned

    return AttachmentSanitized(
        filename=filename,
        content_type=content_type,
        size_bytes=size,
        allowed=True,
        extracted_text=extracted_text,
    )


def sanitize_email(raw: RawEmailPayload) -> SanitizedEmailEvent:
    """Full sanitization pipeline for an email payload."""
    start_time = time.time()

    risk_flags: list[RiskFlagType] = []
    injection_patterns: list[str] = []

    # --- Original sizes ---
    raw_subject = raw.get_subject()
    raw_body = raw.get_body()
    raw_body_plain = raw.get_body_plain()
    raw_attachments = raw.attachments or []

    original_sizes = OriginalSizes(
        subject=len(raw_subject),
        body=len(raw_body),
        attachments_count=len(raw_attachments),
        total_attachment_bytes=sum(
            int(a.get("size", a.get("size_bytes", 0))) for a in raw_attachments
        ),
    )

    # --- Subject sanitization ---
    subject = raw_subject
    subject, sub_html = strip_html(subject)
    subject, sub_unicode = clean_unicode(subject)
    subject, sub_injections = redact_injections(subject)
    subject, sub_secrets = redact_secrets(subject)
    subject, sub_truncated = truncate(subject, MAX_SUBJECT_LENGTH)

    # --- Body sanitization ---
    # Prefer HTML body for stripping, fall back to plain
    body_had_html = False
    if raw.has_html():
        body = raw.get_body_html()
        body, body_had_html = strip_html(body)
    else:
        body = raw_body_plain

    body, body_unicode = clean_unicode(body)
    body, body_injections = redact_injections(body)
    body, body_secrets = redact_secrets(body)
    body, body_truncated = truncate(body, MAX_BODY_LENGTH)

    # --- Attachments ---
    sanitized_attachments = [sanitize_attachment(a) for a in raw_attachments]
    blocked_count = sum(1 for a in sanitized_attachments if not a.allowed)

    # --- Aggregate risk flags ---
    html_detected = sub_html or body_had_html
    if html_detected:
        risk_flags.append(RiskFlagType.HTML_DETECTED)

    all_injections = list(set(sub_injections + body_injections))
    if all_injections:
        risk_flags.append(RiskFlagType.INJECTION_DETECTED)
        injection_patterns = all_injections

    if sub_unicode or body_unicode:
        risk_flags.append(RiskFlagType.UNICODE_SUSPICIOUS)

    if blocked_count > 0:
        risk_flags.append(RiskFlagType.ATTACHMENT_BLOCKED)

    total_secrets = sub_secrets + body_secrets
    if total_secrets > 0:
        risk_flags.append(RiskFlagType.SECRET_DETECTED)

    if HIDDEN_ELEMENT_RE.search(raw.get_body_html() or ""):
        risk_flags.append(RiskFlagType.HIDDEN_CONTENT)

    was_truncated = sub_truncated or body_truncated
    if original_sizes.body > MAX_BODY_LENGTH or original_sizes.subject > MAX_SUBJECT_LENGTH:
        risk_flags.append(RiskFlagType.OVERSIZED)

    # --- Risk score ---
    risk_score = _calculate_risk_score(risk_flags, len(all_injections))

    # --- Build result ---
    processing_time = (time.time() - start_time) * 1000

    return SanitizedEmailEvent(
        provider=raw.provider or "generic",
        received_at=raw.timestamp if raw.timestamp else datetime.utcnow(),
        from_addr=raw.get_from(),
        to_addrs=raw.get_to(),
        subject_sanitized=subject,
        body_sanitized=body,
        attachments_sanitized=sanitized_attachments,
        risk=RiskInfo(
            flags=risk_flags,
            injection_detected=RiskFlagType.INJECTION_DETECTED in risk_flags,
            truncated=was_truncated,
            risk_score=risk_score,
            injection_patterns_found=injection_patterns,
        ),
        meta=SanitizationMeta(
            original_sizes=original_sizes,
            sanitizer_version=SANITIZER_VERSION,
            processing_time_ms=round(processing_time, 2),
            html_stripped=html_detected,
            unicode_cleaned=sub_unicode or body_unicode,
            secrets_redacted=total_secrets,
        ),
    )


def _calculate_risk_score(flags: list[RiskFlagType], injection_count: int) -> int:
    """Calculate a 0-100 risk score based on flags."""
    score = 0

    weights = {
        RiskFlagType.INJECTION_DETECTED: 40,
        RiskFlagType.SCRIPT_DETECTED: 30,
        RiskFlagType.HIDDEN_CONTENT: 25,
        RiskFlagType.SECRET_DETECTED: 20,
        RiskFlagType.HTML_DETECTED: 10,
        RiskFlagType.UNICODE_SUSPICIOUS: 10,
        RiskFlagType.ATTACHMENT_BLOCKED: 15,
        RiskFlagType.OVERSIZED: 5,
    }

    for flag in flags:
        score += weights.get(flag, 5)

    # Extra points for multiple injection patterns
    if injection_count > 1:
        score += (injection_count - 1) * 10

    return min(score, 100)
