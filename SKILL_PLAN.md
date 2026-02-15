# teammate_skill.md
# OpenClaw Hackathon — Skill / Agent Integration Layer

## Your Scope: Build the OpenClaw Skill (Agent-Facing Layer)

I’m building the filtering + sanitization server.
You’ll build the OpenClaw skill that consumes sanitized events and turns them into useful agent behavior.

We are strictly separating concerns:

Filtering Server (me) → Sanitized JSON → OpenClaw Skill (you)

The agent must NEVER directly consume raw webhooks.

---

# 1. Goal

Create an OpenClaw skill that:

- Receives sanitized email events from the filtering server
- Stores or queries recent events
- Allows the agent to answer questions like:
  - “What are my newest emails?”
  - “Summarize today’s emails”
  - “Any risky emails?”
- Displays risk flags clearly
- Never processes raw unsanitized content

---

# 2. Data Contract (What You Receive)

The filtering server will POST this JSON to your skill endpoint:

SanitizedEmailEvent:

{
  "event_id": "...",
  "provider": "generic",
  "received_at": "...",
  "from_addr": "...",
  "to_addrs": [...],
  "subject_sanitized": "...",
  "body_sanitized": "...",
  "attachments_sanitized": [...],
  "risk": {
    "flags": ["html_detected", "injection_detected"],
    "injection_detected": true,
    "truncated": false
  },
  "meta": {
    "original_sizes": {...},
    "sanitizer_version": "v1"
  }
}

Important:
- You must treat this as already sanitized.
- Do not attempt to "re-sanitize".
- Use risk flags in decision logic.

---

# 3. Skill Responsibilities

## 3.1 Ingestion Endpoint

Expose endpoint:

POST /events/email

Store events in:
- memory (hackathon)
- or lightweight DB (sqlite/postgres)

Must support:
- idempotency by event_id
- retrieval by time
- filtering by risk flags

---

## 3.2 Query Functions

Expose callable functions/tools to agent:

1. list_recent_emails(limit=10)
2. list_unread_or_recent(limit=10)
3. summarize_recent_emails()
4. list_risky_emails()
5. search_emails(query_string)

The skill should:
- Only operate on sanitized_body
- Never store raw HTML
- Respect truncation metadata

---

## 3.3 Agent Behavior

The skill must:

- Include risk flags in responses when relevant
- Warn if injection_detected is true
- Highlight truncated content
- Never claim content is “safe” — only “sanitized + flagged”

---

## 4. Storage Schema (Suggested)

Table: sanitized_emails

- event_id (primary key)
- received_at
- from_addr
- subject
- body
- risk_flags (json)
- injection_detected (bool)
- truncated (bool)

Indexes:
- received_at
- injection_detected

---

## 5. Demo Flow

1. Filtering server receives email
2. Filtering server sanitizes
3. Filtering server POSTs to your skill
4. Agent can now answer:
   - “What are my latest emails?”
   - “Any suspicious ones?”
   - “Summarize today’s inbox”

---

## 6. Stretch Goals

- Add simple vector search over sanitized_body
- Add risk-based ranking
- Add “safe preview” vs “full sanitized text”
- Add filtering by sender domain

---

## 7. Deliverables

- Skill service running
- Endpoint for sanitized event ingestion
- Queryable interface for agent
- Clean logging
- Basic persistence
- Demo-ready

You’re building the intelligence layer.
I’m building the safety layer.

Together:
Safety → Skill → Agent

-------------------------------------------------------------------------------

