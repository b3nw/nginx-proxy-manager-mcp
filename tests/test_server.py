"""Tests for the server module and its FastMCP initialization."""

import pytest

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
