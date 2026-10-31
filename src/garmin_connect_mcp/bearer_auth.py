"""HTTP Bearer token authentication for the MCP layer.

This protects the MCP HTTP endpoint itself (clients connecting to the server).
Unrelated to Garmin Connect account authentication (garminconnect OAuth),
which is handled by auth.py / setup scripts.
"""

import os

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Rejects requests without a valid Bearer token."""

    async def dispatch(self, request, call_next):
        token = os.getenv("MCP_AUTH_TOKEN")
        if not token:
            return await call_next(request)
        if request.headers.get("Authorization") != f"Bearer {token}":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


def bearer_auth_middleware() -> list[Middleware]:
    """Returns the Starlette middleware stack for FastMCP."""
    return [Middleware(BearerAuthMiddleware)]
