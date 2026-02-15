"""ClawGuard FastAPI application."""

from fastapi import FastAPI

app = FastAPI(
    title="ClawGuard",
    description="Secure inbound sanitization layer for LLM agents",
    version="0.1.0",
)


@app.get("/health")
async def health():
    return {"status": "ok"}
