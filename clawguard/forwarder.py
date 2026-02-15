"""Forwarding module - sends sanitized events to the skill endpoint and/or OpenClaw hooks."""

from __future__ import annotations

import hashlib
import hmac
import logging

import httpx

from .config import Config
from .models import SanitizedEmailEvent

logger = logging.getLogger("clawguard.forwarder")


def _sign_payload(payload: str, secret: str) -> str:
    """Create HMAC-SHA256 signature for a payload."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


async def forward_to_skill(event: SanitizedEmailEvent, config: Config) -> bool:
    """Forward sanitized event to the teammate's skill endpoint."""
    if not config.skill_endpoint:
        logger.debug("No skill endpoint configured, skipping forward")
        return False

    payload = event.model_dump_json()
    signature = _sign_payload(payload, config.forward_secret)

    headers = {
        "Content-Type": "application/json",
        "X-ClawGuard-Signature": signature,
        "X-ClawGuard-Event-Id": event.event_id,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(config.skill_endpoint, content=payload, headers=headers)
            if resp.status_code in (200, 201, 202):
                logger.info(f"Forwarded event {event.event_id} to skill (status={resp.status_code})")
                return True
            else:
                logger.warning(f"Skill endpoint returned {resp.status_code}: {resp.text[:200]}")
                return False
    except httpx.HTTPError as e:
        logger.error(f"Failed to forward to skill: {e}")
        return False


async def forward_to_openclaw(event: SanitizedEmailEvent, config: Config) -> bool:
    """Forward sanitized event to OpenClaw hooks/agent endpoint."""
    if not config.openclaw_hooks_url or not config.openclaw_hooks_token:
        logger.debug("No OpenClaw hooks configured, skipping")
        return False

    risk_summary = ""
    if event.risk.injection_detected:
        risk_summary = f" [INJECTION DETECTED - patterns: {', '.join(event.risk.injection_patterns_found)}]"

    message = (
        f"New email from {event.from_addr}.\n"
        f"Subject: {event.subject_sanitized}\n"
        f"Risk score: {event.risk.risk_score}/100{risk_summary}\n"
        f"Body preview: {event.body_sanitized[:500]}"
    )

    payload = {
        "message": message,
        "name": "clawguard-email",
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.openclaw_hooks_token}",
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = config.openclaw_hooks_url.rstrip("/") + "/agent"
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201, 202):
                logger.info(f"Forwarded event {event.event_id} to OpenClaw hooks")
                return True
            else:
                logger.warning(f"OpenClaw hooks returned {resp.status_code}: {resp.text[:200]}")
                return False
    except httpx.HTTPError as e:
        logger.error(f"Failed to forward to OpenClaw: {e}")
        return False
