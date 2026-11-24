"""Request guards as plain ASGI middleware: body size limit, origin check for state-changing
requests, per-client rate limits, and security headers."""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from typing import Any, Awaitable, Callable

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
     b"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
]


async def _reject(send: Send, status: int, message: str) -> None:
    body = json.dumps({"detail": message}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), *SECURITY_HEADERS]})
    await send({"type": "http.response.body", "body": body})


class _TooLarge(Exception):
    pass


class RateLimiter:
    """Fixed-window counter per (client, bucket). In-process: adequate for a single-instance demo."""

    def __init__(self, limits: dict[str, int], window_s: float = 60.0) -> None:
        self.limits, self.window = limits, window_s
        self._hits: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, client: str, bucket: str) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits[(client, bucket)] if now - t < self.window]
            if len(hits) >= self.limits[bucket]:
                self._hits[(client, bucket)] = hits
                return False
            hits.append(now)
            self._hits[(client, bucket)] = hits
            return True


class Guards:
    def __init__(self, app: ASGIApp, *, allowed_origins: set[str], max_body: int, limiter: RateLimiter) -> None:
        self.app, self.allowed_origins, self.max_body, self.limiter = app, allowed_origins, max_body, limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        method, path = scope["method"], scope["path"]

        if method in UNSAFE_METHODS:
            origin = headers.get("origin")
            if origin is not None and origin not in self.allowed_origins:
                await _reject(send, 403, "origin not allowed")
                return
            client = (scope.get("client") or ("unknown", 0))[0]
            bucket = "live" if path.startswith("/api/live") else "write"
            if not self.limiter.allow(client, bucket):
                await _reject(send, 429, "rate limit exceeded")
                return
        declared = headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_body):
            await _reject(send, 413, "request body too large")
            return

        received = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    raise _TooLarge
            return message

        async def secured_send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message.get("headers", []), *SECURITY_HEADERS]}
            await send(message)

        try:
            await self.app(scope, limited_receive, secured_send)
        except _TooLarge:
            await _reject(send, 413, "request body too large")
