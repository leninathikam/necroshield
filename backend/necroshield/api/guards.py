"""Request guards as plain ASGI middleware: body size limit, origin check for state-changing
requests, per-client and global rate limits, and security headers.

Client identity for rate limiting. Behind a reverse proxy the socket peer is the proxy, so every
visitor would share one bucket. Configure exactly one of:
  - client_ip_header: a header the proxy overwrites (never trusts from the client), or
  - proxy_hops: the number of trusted proxies appending to X-Forwarded-For. The key is the entry
    that many places from the right, which a client cannot forge by sending its own header.
Without either, the socket peer is used, which is correct when clients connect directly.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

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


class RateLimiter:
    """Fixed-window counter per (client, bucket). In-process: adequate for a single-instance demo."""

    def __init__(self, limits: dict[str, int], window_s: float = 60.0) -> None:
        self.limits, self.window = limits, window_s
        self._hits: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, client: str, bucket: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:  # evict idle keys so spoofed or one-off clients cannot grow memory
                self._hits = defaultdict(list, {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window})
            hits = [t for t in self._hits[(client, bucket)] if now - t < self.window]
            if len(hits) >= self.limits[bucket]:
                self._hits[(client, bucket)] = hits
                return False
            hits.append(now)
            self._hits[(client, bucket)] = hits
            return True


GLOBAL = "*"


def same_origin(origin: str, host: str | None) -> bool:
    """True when a browser Origin names this server. Browsers set Origin themselves, so a
    cross-site page cannot claim our host; non-browser clients are not stopped by this check."""
    parts = urlsplit(origin)
    return parts.scheme in ("http", "https") and bool(host) and parts.netloc.lower() == host.lower()


class Guards:
    def __init__(self, app: ASGIApp, *, allowed_origins: set[str], max_body: int, limiter: RateLimiter,
                 proxy_hops: int = 0, client_ip_header: str | None = None) -> None:
        self.app, self.allowed_origins, self.max_body, self.limiter = app, allowed_origins, max_body, limiter
        self.proxy_hops = max(0, proxy_hops)
        self.client_ip_header = client_ip_header.lower() if client_ip_header else None

    def client_key(self, scope: Scope, headers: dict[str, str]) -> str:
        peer = (scope.get("client") or ("unknown", 0))[0]
        if self.client_ip_header:
            value = headers.get(self.client_ip_header, "").strip()
            return value[:64] or peer
        if self.proxy_hops:
            hops = [h.strip() for h in headers.get("x-forwarded-for", "").split(",") if h.strip()]
            if len(hops) >= self.proxy_hops:
                return hops[-self.proxy_hops][:64]
        return peer

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        method, path = scope["method"], scope["path"]

        client = self.client_key(scope, headers)
        scope.setdefault("state", {})["client_key_hash"] = hashlib.sha256(client.encode()).hexdigest()[:12]
        buckets: list[tuple[str, str]] = []
        if method in UNSAFE_METHODS:
            # The origin check stops cross-site browser writes; it does not authenticate anyone.
            origin = headers.get("origin")
            if origin is not None and origin not in self.allowed_origins and not same_origin(origin, headers.get("host")):
                await _reject(send, 403, "origin not allowed")
                return
            if path.startswith("/api/live"):
                buckets.append((client, "live"))
            elif path == "/api/benchmark":
                buckets.append((client, "benchmark"))
            buckets += [(client, "write"), (GLOBAL, "global_write")]
        elif path.startswith("/api/"):
            buckets.append((client, "read"))
        for key, bucket in buckets:
            if bucket in self.limiter.limits and not self.limiter.allow(key, bucket):
                await _reject(send, 429, "rate limit exceeded" if key != GLOBAL else "server is busy; try again shortly")
                return
        declared = headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_body):
            await _reject(send, 413, "request body too large")
            return

        received, too_large, started = 0, False, False

        async def limited_receive() -> dict[str, Any]:
            # Streamed bodies are counted as they arrive. Past the limit the app sees a disconnect,
            # and the 413 below replaces whatever error response it would have produced.
            nonlocal received, too_large
            if too_large:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_body:
                    too_large = True
                    return {"type": "http.disconnect"}
            return message

        async def secured_send(message: dict[str, Any]) -> None:
            nonlocal started
            if too_large:
                return
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": [*message.get("headers", []), *SECURITY_HEADERS]}
            await send(message)

        try:
            await self.app(scope, limited_receive, secured_send)
        except Exception:
            if not too_large:
                raise
        if too_large and not started:
            await _reject(send, 413, "request body too large")
