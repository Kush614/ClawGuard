"""Configuration for ClawGuard server."""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class Config(BaseModel):
    # Server
    host: str = "0.0.0.0"
    port: int = 8000

    # Security
    webhook_secret: str = Field(default_factory=lambda: os.getenv("CLAWGUARD_WEBHOOK_SECRET", "clawguard-dev-secret"))
    require_verification: bool = Field(default_factory=lambda: os.getenv("CLAWGUARD_REQUIRE_VERIFICATION", "false").lower() == "true")

    # Rate limiting
    rate_limit_per_minute: int = 60
    max_payload_size: int = 25 * 1024 * 1024  # 25MB

    # Forwarding
    skill_endpoint: str = Field(default_factory=lambda: os.getenv("CLAWGUARD_SKILL_ENDPOINT", ""))
    forward_secret: str = Field(default_factory=lambda: os.getenv("CLAWGUARD_FORWARD_SECRET", "clawguard-forward-secret"))

    # Storage
    db_path: Path = Field(default_factory=lambda: Path(os.getenv("CLAWGUARD_DB_PATH", "clawguard.db")))

    # OpenClaw integration
    openclaw_hooks_url: str = Field(default_factory=lambda: os.getenv("OPENCLAW_HOOKS_URL", ""))
    openclaw_hooks_token: str = Field(default_factory=lambda: os.getenv("OPENCLAW_HOOKS_TOKEN", ""))

    # Gmail / GCP integration
    gmail_enabled: bool = Field(default_factory=lambda: os.getenv("GMAIL_ENABLED", "false").lower() == "true")
    gmail_credentials_path: Path = Field(default_factory=lambda: Path(os.getenv("GMAIL_CREDENTIALS_PATH", "gmail_credentials.json")))
    gmail_token_path: Path = Field(default_factory=lambda: Path(os.getenv("GMAIL_TOKEN_PATH", "gmail_token.json")))
    gcp_pubsub_topic: str = Field(default_factory=lambda: os.getenv("GCP_PUBSUB_TOPIC", ""))
    gmail_poll_interval_seconds: int = Field(default_factory=lambda: int(os.getenv("GMAIL_POLL_INTERVAL", "60")))
    gmail_max_fetch: int = Field(default_factory=lambda: int(os.getenv("GMAIL_MAX_FETCH", "10")))


def load_config() -> Config:
    return Config()
