"""Small ASGI ingress boundary for the loopback-only development API."""

import os
from urllib.parse import urlparse

from starlette.responses import JSONResponse

MAX_REQUEST_BYTES = 4096
ALLOWED_ORIGINS = frozenset({"http://localhost:3017", "http://127.0.0.1:3017",
                            "http://localhost:8017", "http://127.0.0.1:8017"})


def configured_origins() -> frozenset[str]:
    origin = os.environ.get("NECROSHIELD_FRONTEND_ORIGIN")
    if origin is None:
        return ALLOWED_ORIGINS
    parsed = urlparse(origin)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path
            or parsed.params or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("NECROSHIELD_FRONTEND_ORIGIN must be one exact HTTP(S) origin without path or credentials")
    return ALLOWED_ORIGINS | {origin}


class LocalIngressBoundary:
    def __init__(self, app, allowed_origins: frozenset[str]):
        self.app = app
        self.allowed_origins = allowed_origins

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1")
                   for key, value in scope.get("headers", [])}
        origin = headers.get("origin")
        if origin is not None and origin not in self.allowed_origins:
            await JSONResponse({"detail": "Origin is outside the local arena scope"}, status_code=403)(scope, receive, send)
            return
        length = headers.get("content-length")
        if length is not None:
            try:
                if int(length) < 0:
                    raise ValueError()
                too_large = int(length) > MAX_REQUEST_BYTES
            except ValueError:
                await JSONResponse({"detail": "Invalid content length"}, status_code=400)(scope, receive, send)
                return
            if too_large:
                await JSONResponse({"detail": "Request exceeds the arena input budget"}, status_code=413)(scope, receive, send)
                return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > MAX_REQUEST_BYTES:
                await JSONResponse({"detail": "Request exceeds the arena input budget"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        consumed = False

        async def replay_receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
