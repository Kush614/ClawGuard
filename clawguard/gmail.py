"""Gmail API integration for ClawGuard.

Connects to Gmail via Google API to fetch emails, parse them into
RawEmailPayload, and feed them into the sanitization pipeline.

Supports:
- OAuth2 credentials (user consent flow)
- Service account credentials
- GCP Pub/Sub push notifications for real-time email arrival
- Polling for batch fetch
"""

from __future__ import annotations

import base64
import email
import email.utils
import json
import logging
from datetime import datetime
from email.message import Message
from pathlib import Path
from typing import Any

from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from .models import RawEmailPayload

logger = logging.getLogger("clawguard.gmail")

# Gmail API scopes — read-only is all we need
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

TOKEN_PATH = Path("gmail_token.json")
CREDENTIALS_PATH = Path("gmail_credentials.json")


class GmailClient:
    """Wrapper around Gmail API for fetching and parsing emails."""

    def __init__(
        self,
        credentials_path: Path | str = CREDENTIALS_PATH,
        token_path: Path | str = TOKEN_PATH,
    ):
        self.credentials_path = Path(credentials_path)
        self.token_path = Path(token_path)
        self._service = None
        self._creds: Credentials | None = None

    def authenticate(self) -> None:
        """Authenticate with Gmail API using OAuth2."""
        creds = None

        # Load existing token
        if self.token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)
            except Exception as e:
                logger.warning(f"Failed to load token: {e}")

        # Refresh or run consent flow
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(GoogleRequest())
            except Exception as e:
                logger.warning(f"Token refresh failed: {e}")
                creds = None

        if not creds or not creds.valid:
            if not self.credentials_path.exists():
                raise FileNotFoundError(
                    f"Gmail credentials not found at {self.credentials_path}. "
                    "Download OAuth2 credentials from Google Cloud Console "
                    "(APIs & Services > Credentials > OAuth 2.0 Client IDs) "
                    "and save as gmail_credentials.json"
                )
            flow = InstalledAppFlow.from_client_secrets_file(
                str(self.credentials_path), SCOPES
            )
            creds = flow.run_local_server(port=0)

            # Save token for future runs
            self.token_path.write_text(creds.to_json())
            logger.info(f"Gmail token saved to {self.token_path}")

        self._creds = creds
        self._service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail API authenticated successfully")

    @property
    def service(self):
        if not self._service:
            self.authenticate()
        return self._service

    def setup_watch(self, topic_name: str) -> dict:
        """Set up Gmail push notifications via GCP Pub/Sub.

        Args:
            topic_name: Full Pub/Sub topic name, e.g.
                        "projects/my-project/topics/gmail-notifications"

        Returns:
            Watch response with historyId and expiration.
        """
        request_body = {
            "topicName": topic_name,
            "labelIds": ["INBOX"],
        }
        result = self.service.users().watch(userId="me", body=request_body).execute()
        logger.info(f"Gmail watch set up: historyId={result.get('historyId')}, "
                     f"expiration={result.get('expiration')}")
        return result

    def stop_watch(self) -> None:
        """Stop Gmail push notifications."""
        self.service.users().stop(userId="me").execute()
        logger.info("Gmail watch stopped")

    def get_history(self, start_history_id: str, history_types: list[str] | None = None) -> list[str]:
        """Get message IDs from history since a given historyId.

        Used when receiving Pub/Sub notifications.
        """
        if history_types is None:
            history_types = ["messageAdded"]

        message_ids = []
        try:
            results = (
                self.service.users()
                .history()
                .list(userId="me", startHistoryId=start_history_id, historyTypes=history_types)
                .execute()
            )

            for record in results.get("history", []):
                for msg_added in record.get("messagesAdded", []):
                    msg = msg_added.get("message", {})
                    msg_id = msg.get("id")
                    if msg_id:
                        # Only process INBOX messages
                        labels = msg.get("labelIds", [])
                        if "INBOX" in labels:
                            message_ids.append(msg_id)

        except Exception as e:
            # historyId might be too old
            logger.error(f"Failed to get history: {e}")

        return message_ids

    def fetch_message(self, message_id: str) -> RawEmailPayload | None:
        """Fetch a single Gmail message and parse it into RawEmailPayload."""
        try:
            msg = (
                self.service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )
            return self._parse_gmail_message(msg)
        except Exception as e:
            logger.error(f"Failed to fetch message {message_id}: {e}")
            return None

    def fetch_recent_messages(self, max_results: int = 10, query: str = "in:inbox") -> list[RawEmailPayload]:
        """Fetch recent messages from Gmail inbox."""
        try:
            results = (
                self.service.users()
                .messages()
                .list(userId="me", q=query, maxResults=max_results)
                .execute()
            )
        except Exception as e:
            logger.error(f"Failed to list messages: {e}")
            return []

        messages = results.get("messages", [])
        payloads = []

        for msg_meta in messages:
            payload = self.fetch_message(msg_meta["id"])
            if payload:
                payloads.append(payload)

        logger.info(f"Fetched {len(payloads)} messages from Gmail")
        return payloads

    def _parse_gmail_message(self, msg: dict[str, Any]) -> RawEmailPayload:
        """Parse a Gmail API message into our RawEmailPayload model."""
        headers = {}
        payload = msg.get("payload", {})

        # Extract headers
        for header in payload.get("headers", []):
            name = header["name"].lower()
            headers[name] = header["value"]

        from_addr = headers.get("from", "")
        to_addr = headers.get("to", "")
        subject = headers.get("subject", "")
        date_str = headers.get("date", "")

        # Parse To into list
        to_list = [addr.strip() for addr in to_addr.split(",")] if to_addr else []

        # Extract body
        body_plain = ""
        body_html = ""
        attachments = []

        self._extract_parts(payload, body_parts={"plain": [], "html": []}, attachments=attachments)

        # Collect body parts
        parts_store: dict[str, list[str]] = {"plain": [], "html": []}
        self._extract_parts(payload, body_parts=parts_store, attachments=attachments)
        body_plain = "\n".join(parts_store["plain"])
        body_html = "\n".join(parts_store["html"])

        # Parse timestamp
        timestamp = None
        if date_str:
            try:
                parsed = email.utils.parsedate_to_datetime(date_str)
                timestamp = parsed.isoformat()
            except Exception:
                pass

        # Parse from address (extract just email from "Name <email>" format)
        from_parsed = email.utils.parseaddr(from_addr)
        from_email = from_parsed[1] if from_parsed[1] else from_addr

        return RawEmailPayload(
            from_address=from_email,
            to_addrs=[email.utils.parseaddr(a)[1] or a for a in to_list],
            subject=subject,
            body_plain=body_plain if body_plain else None,
            body_html=body_html if body_html else None,
            attachments=attachments if attachments else None,
            headers=headers,
            provider="gmail",
            timestamp=timestamp,
        )

    def _extract_parts(
        self,
        part: dict[str, Any],
        body_parts: dict[str, list[str]],
        attachments: list[dict[str, Any]],
    ) -> None:
        """Recursively extract body text and attachments from MIME parts."""
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        parts = part.get("parts", [])

        # Recurse into multipart
        if parts:
            for sub_part in parts:
                self._extract_parts(sub_part, body_parts, attachments)
            return

        # Check for attachment
        filename = part.get("filename", "")
        if filename and body.get("attachmentId"):
            attachments.append({
                "filename": filename,
                "content_type": mime_type,
                "size": body.get("size", 0),
                "attachment_id": body.get("attachmentId"),
            })
            return

        # Decode body data
        data = body.get("data", "")
        if not data:
            return

        try:
            decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
        except Exception:
            return

        if mime_type == "text/plain":
            body_parts["plain"].append(decoded)
        elif mime_type == "text/html":
            body_parts["html"].append(decoded)
