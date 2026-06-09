"""Tests for ServerRegistry."""

import pytest

from npm_mcp.config import settings
from npm_mcp.server import ServerRegistry


def test_registry_fallback_to_single_server(monkeypatch):
    """Test that registry falls back to single-server settings when empty."""
    monkeypatch.setattr(settings, "api_url", "http://test-url:81/api")
    monkeypatch.setattr(settings, "identity", "test-user")
    monkeypatch.setattr(settings, "secret", "test-pass")

    registry = ServerRegistry(configs=[], default=None)

    assert registry.list_names() == ["default"]
    assert registry.get_default() == "default"

    client = registry.get()
    assert client.base_url == "http://test-url:81/api"
    assert client._identity == "test-user"


def test_registry_multiple_servers():
    """Test that multiple servers are correctly registered."""
    configs = [
        {"name": "prod", "url": "http://prod:81/api", "identity": "p", "secret": "ps"},
        {"name": "dev", "url": "http://dev:81/api", "identity": "d", "secret": "ds"},
    ]

    registry = ServerRegistry(configs=configs, default="prod")

    assert set(registry.list_names()) == {"prod", "dev"}
    assert registry.get_default() == "prod"

    prod_client = registry.get("prod")
    assert prod_client.base_url == "http://prod:81/api"

    dev_client = registry.get("dev")
    assert dev_client.base_url == "http://dev:81/api"


def test_registry_get_default_fallback():
    """Test that get() falls back to default server when name is None/empty."""
    configs = [
        {"name": "prod", "url": "http://prod:81/api", "identity": "p", "secret": "ps"},
        {"name": "dev", "url": "http://dev:81/api", "identity": "d", "secret": "ds"},
    ]

    registry = ServerRegistry(configs=configs, default="dev")

    # Name is None
    client = registry.get(None)
    assert client.base_url == "http://dev:81/api"

    # Name is empty string
    client_empty = registry.get("")
    assert client_empty.base_url == "http://dev:81/api"


def test_registry_single_client_no_default_specified():
    """Test that get() succeeds if there is only 1 server, even if no default is specified."""
    configs = [
        {"name": "only-one", "url": "http://only:81/api", "identity": "o", "secret": "os"}
    ]

    registry = ServerRegistry(configs=configs, default=None)

    assert registry.get_default() is None
    client = registry.get()
    assert client.base_url == "http://only:81/api"


def test_registry_multiple_clients_no_default_raises():
    """Test that get() raises KeyError if multiple servers are defined but no default is set."""
    configs = [
        {"name": "prod", "url": "http://prod:81/api", "identity": "p", "secret": "ps"},
        {"name": "dev", "url": "http://dev:81/api", "identity": "d", "secret": "ds"},
    ]

    registry = ServerRegistry(configs=configs, default=None)

    with pytest.raises(KeyError, match="Multiple servers configured but no default server"):
        registry.get()


def test_registry_invalid_name_raises():
    """Test that get() raises KeyError for non-existent server names."""
    configs = [
        {"name": "prod", "url": "http://prod:81/api", "identity": "p", "secret": "ps"},
    ]

    registry = ServerRegistry(configs=configs, default="prod")

    with pytest.raises(KeyError, match="Server 'non-existent' not found"):
        registry.get("non-existent")
