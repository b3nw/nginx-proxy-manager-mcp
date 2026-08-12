"""Bearer token authentication middleware for HTTP transport."""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_AUTH_HEADERS = {"WWW-Authenticate": "Bearer"}


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Reject HTTP requests missing a valid Authorization: Bearer <token> header."""

    def __init__(self, app, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        # RFC 7235 §2.1: auth scheme is case-insensitive
        if not auth[:7].lower() == "bearer ":
            return JSONResponse(
                {"error": "Missing bearer token"}, status_code=401, headers=_AUTH_HEADERS
            )

        supplied = auth[7:]
        if not hmac.compare_digest(supplied, self._token):
            return JSONResponse({"error": "Invalid bearer token"}, status_code=403)

        return await call_next(request)
