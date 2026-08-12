"""Bearer token authentication middleware for HTTP transport."""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

_AUTH_HEADERS = {"WWW-Authenticate": "Bearer"}


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Reject HTTP requests missing a valid Authorization: Bearer *** header."""

    def __init__(self, app: ASGIApp, token: str):
        super().__init__(app)
        self._token = token

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path == "/health":
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        # RFC 7235 §2.1: auth scheme is case-insensitive
        if auth[:7].lower() != "bearer ":
            return JSONResponse(
                {"error": "Missing bearer token"}, status_code=401, headers=_AUTH_HEADERS
            )

        supplied = auth[7:]
        try:
            # hmac.compare_digest raises TypeError if either operand is non-ASCII;
            # encoding to bytes prevents this crash and is side-channel safe.
            supplied_bytes = supplied.encode("utf-8", "surrogateescape")
            token_bytes = self._token.encode("utf-8", "surrogateescape")
            is_valid = hmac.compare_digest(supplied_bytes, token_bytes)
        except (TypeError, UnicodeEncodeError):
            is_valid = False

        if not is_valid:
            # RFC 6750 §3: invalid token should yield 401 with error="invalid_token"
            return JSONResponse(
                {"error": "Invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        return await call_next(request)
