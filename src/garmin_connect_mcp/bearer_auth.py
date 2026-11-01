"""HTTP Bearer token authentication for the MCP server.

Pure ASGI middleware: applies before the MCP transport, does not
buffer streaming responses (SSE), and emits the WWW-Authenticate
challenge required for client auth discovery.

Activated only when the MCP_AUTH_TOKEN environment variable is set.
Without the variable, all requests pass through (local/no-auth mode).
"""

import json
import os

from starlette.types import ASGIApp, Receive, Scope, Send


class BearerAuthASGI:
    """Rejects requests without a valid Bearer token.

    Accepts 'Authorization: Bearer <token>' (RFC 6750) and
    'Authorization: <token>' (raw, emitted by some clients).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        token = os.getenv("MCP_AUTH_TOKEN")
        if not token:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path.startswith("/.well-known/"):
            await self.app(scope, receive, send)
            return
        headers = {
            k.decode().lower(): v.decode()
            for k, v in scope.get("headers", [])
        }
        auth = headers.get("authorization", "")
        if auth not in (token, f"Bearer {token}"):
            body = json.dumps({"error": "unauthorized"}).encode()
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Bearer realm="garmin-mcp"'),
                    (b"content-length", str(len(body)).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)