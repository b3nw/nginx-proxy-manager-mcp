"""Tests for bearer token authentication middleware."""

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from npm_mcp.auth import BearerAuthMiddleware

TOKEN = "test-secret-token"


async def echo(request: Request):
    return PlainTextResponse("ok")


async def health(request: Request):
    return PlainTextResponse("healthy")


@pytest.fixture
def app():
    a = Starlette(routes=[Route("/mcp", echo), Route("/health", health)])
    a.add_middleware(BearerAuthMiddleware, token=TOKEN)
    return a


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


class TestBearerAuth:
    def test_missing_token_returns_401(self, client):
        r = client.get("/mcp")
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == "Bearer"

    def test_wrong_token_returns_401(self, client):
        r = client.get("/mcp", headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == 'Bearer error="invalid_token"'

    def test_valid_token_passes(self, client):
        r = client.get("/mcp", headers={"Authorization": f"Bearer {TOKEN}"})
        assert r.status_code == 200
        assert r.text == "ok"

    def test_bearer_scheme_case_insensitive(self, client):
        r = client.get("/mcp", headers={"Authorization": f"bearer {TOKEN}"})
        assert r.status_code == 200

    def test_health_bypasses_auth(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.text == "healthy"
