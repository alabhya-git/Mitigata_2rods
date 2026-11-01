"""Private control-plane gateway. Assessment containers never receive the Claude key."""

from __future__ import annotations

import asyncio
import hmac
import json
import os

from fastapi import FastAPI, HTTPException, Request

from .ai import PRICES, ClaudeClient, api_key_available, load_local_environment
from .config import AISettings


def create_gateway():
    load_local_environment()
    token = os.environ.get("MITIGATA_AI_GATEWAY_TOKEN", "")
    if len(token) < 24:
        raise ValueError("Private AI gateway token is missing or too short")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    async def health():
        return {"status": "ok", "claude_key_configured": api_key_available()}

    @app.post("/v1/messages")
    async def messages(request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
            raise HTTPException(401, "Private control-plane token required")
        body = await request.body()
        if len(body) > 110000:
            raise HTTPException(413, "Case input too large")
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            raise HTTPException(422, "Invalid JSON") from None
        if (
            not isinstance(data, dict)
            or data.get("model") not in PRICES
            or type(data.get("max_tokens")) is not int
            or not 1 <= data.get("max_tokens", 0) <= 4096
        ):
            raise HTTPException(422, "Unapproved model or output limit")
        if set(data) - {"model", "max_tokens", "system", "messages", "tools", "tool_choice"}:
            raise HTTPException(422, "Unsupported API field")
        client = ClaudeClient.__new__(ClaudeClient)
        client.settings = AISettings(timeout=60)
        try:
            return await asyncio.to_thread(client._post, data)
        except RuntimeError as exc:
            raise HTTPException(502, str(exc)) from None

    return app
