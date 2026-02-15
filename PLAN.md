# OpenClaw Hackathon Idea — Secure Inbound Sanitization Layer

## TL;DR
We’re building a security-first **Email → Sanitized Event → Agent** pipeline that prevents prompt injection and unsafe content from ever reaching the LLM.

Phase 1: Email webhook + deterministic sanitization  
Phase 2: GitHub webhook + diff/comment sanitization  

The core idea is simple:
All external content is untrusted. Agents never see raw input.

---

## Problem

LLM agents are extremely vulnerable to:

- Prompt injection (“ignore previous instructions…”)
- Tool call manipulation
- Hidden HTML/script payloads
- Secret exfiltration attempts
- Malicious content embedded in attachments
- Markdown/code-based instruction hijacking (GitHub)

Most systems pass raw inbound data directly to the agent.

We want to build a **defensive middleware layer**.

---

## Solution

A Python-based, modular ingress system:

Inbound Webhook  
→ Verification  
→ Normalization  
→ Deterministic Sanitization  
→ Risk Flagging  
→ Structured Safe Payload  
→ Agent  

Key guarantees:

- No raw HTML to agent
- No scripts
- No hidden elements
- Prompt injection patterns flagged/redacted
- Attachments filtered + extracted safely
- Length-limited + normalized
- Risk metadata included

---

## Why This Is Interesting

- Real-world agent security problem
- Immediately useful for OpenClaw-style systems
- Modular and extensible
- Can plug into any agent runtime
- Demonstrates practical AI safety engineering

---

## Phase 1 (Hackathon Scope)

- Email webhook endpoint
- Shared-secret verification
- Canonical EmailEvent schema
- Sanitization pipeline:
  - HTML stripping
  - Unicode cleanup
  - Injection pattern detection
  - Truncation
  - Attachment allowlist
- Output sanitized JSON to downstream agent

---

## Phase 2 (Future)

- GitHub webhook ingestion
- Diff truncation
- Markdown sanitization
- Secret scanning
- Repo-level risk scoring

---

## Tech Stack

- Python
- FastAPI
- Deterministic regex-based injection guard
- Pluggable sinks (stdout / DB / webhook)

---

## Vision

We’re not building “another agent.”

We’re building the **security layer agents should have by default.**

If this works well, it becomes:

> “IronClaw-style safety, but Python-native and composable.”

Let’s build the agent firewall.

