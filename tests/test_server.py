"""Tests for the server module and its FastMCP initialization."""


def test_server_imports():
    """Ensure that the server and mcp instance can be imported without errors."""
    from npm_mcp.server import mcp

    assert mcp is not None
    assert mcp.name == "npm-mcp"


def test_server_http_app():
    """Ensure that the http_app can be retrieved without AttributeError."""
    from npm_mcp.server import mcp

    app = mcp.http_app()
    assert app is not None


# ---------------------------------------------------------------------------
# HSTS / HTTP/2 parameters on create/update/details
# ---------------------------------------------------------------------------

import json  # noqa: E402

import pytest  # noqa: E402

from npm_mcp import server  # noqa: E402
from npm_mcp.config import NpmInstance  # noqa: E402
from npm_mcp.models import ProxyHost  # noqa: E402


def _tool_fn(tool):
    """Return the underlying coroutine function of a FastMCP tool.

    Depending on the FastMCP version, ``@mcp.tool()`` returns either the
    original function or a ``FunctionTool`` wrapping it.
    """
    return getattr(tool, "fn", tool)


def _make_host(**overrides) -> ProxyHost:
    data = {
        "id": 7,
        "created_on": "2024-01-01T00:00:00Z",
        "modified_on": "2024-01-01T00:00:00Z",
        "owner_user_id": 1,
        "domain_names": ["app.example.com"],
        "forward_host": "192.168.1.100",
        "forward_port": 8080,
        "forward_scheme": "http",
        "enabled": True,
        "ssl_forced": True,
        "hsts_enabled": True,
        "hsts_subdomains": True,
        "http2_support": True,
    }
    data.update(overrides)
    return ProxyHost(**data)


class _FakeClient:
    """Records the kwargs the server tools hand to the NPM client."""

    def __init__(self):
        self.update_kwargs = None
        self.create_kwargs = None

    async def get_proxy_host(self, host_id):
        return _make_host()

    async def update_proxy_host(self, host_id, **kwargs):
        self.update_kwargs = kwargs
        return _make_host()

    async def create_proxy_host(self, **kwargs):
        self.create_kwargs = kwargs
        return _make_host()


@pytest.fixture
def fake_client(monkeypatch):
    client = _FakeClient()
    instance = NpmInstance(
        name="default",
        api_url="http://localhost:81/api",
        identity="a@b",
        secret="x",
        proxy_defaults={"hsts_enabled": False, "http2_support": False},
    )
    monkeypatch.setattr(server, "_resolve", lambda _name: (client, instance))
    monkeypatch.setattr(server, "_check_destructive", lambda: None)
    return client


async def test_update_forwards_hsts_and_http2(fake_client):
    result = await _tool_fn(server.update_proxy_host)(
        host_id=7, hsts_enabled=True, hsts_subdomains=False, http2_support=True
    )
    assert "Successfully updated" in result
    assert fake_client.update_kwargs == {
        "hsts_enabled": True,
        "hsts_subdomains": False,  # explicit False must be forwarded, not dropped
        "http2_support": True,
    }


async def test_update_omits_unset_hsts_and_http2(fake_client):
    await _tool_fn(server.update_proxy_host)(host_id=7, forward_port=9090)
    assert fake_client.update_kwargs == {"forward_port": 9090}


async def test_create_uses_explicit_hsts_and_http2(fake_client):
    await _tool_fn(server.create_proxy_host)(
        domain_names=["app.example.com"],
        forward_host="10.0.0.1",
        forward_port=80,
        hsts_enabled=True,
        hsts_subdomains=True,
        http2_support=True,
    )
    assert fake_client.create_kwargs["hsts_enabled"] is True
    assert fake_client.create_kwargs["hsts_subdomains"] is True
    assert fake_client.create_kwargs["http2_support"] is True


async def test_create_falls_back_to_instance_defaults(fake_client):
    await _tool_fn(server.create_proxy_host)(
        domain_names=["app.example.com"],
        forward_host="10.0.0.1",
        forward_port=80,
    )
    # Instance proxy_defaults override the built-in defaults; the rest come
    # from DEFAULT_PROXY_SETTINGS.
    assert fake_client.create_kwargs["hsts_enabled"] is False
    assert fake_client.create_kwargs["http2_support"] is False
    assert fake_client.create_kwargs["hsts_subdomains"] is False


async def test_details_include_hsts_subdomains(fake_client):
    result = await _tool_fn(server.get_proxy_host_details)(host_id=7)
    details = json.loads(result)
    assert details["ssl"]["hsts_enabled"] is True
    assert details["ssl"]["hsts_subdomains"] is True
    assert details["ssl"]["http2_support"] is True
