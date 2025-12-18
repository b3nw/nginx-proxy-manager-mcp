"""Tests for NpmClient."""

import pytest
from httpx import Response

from npm_mcp.client import NpmClient
from npm_mcp.exceptions import NpmAuthenticationError, NpmConnectionError


@pytest.fixture
def mock_token_response():
    """Mock token response data."""
    return {
        "token": "test-jwt-token",
        "expires": "2099-12-31T23:59:59Z",
    }


@pytest.fixture
def mock_proxy_hosts():
    """Mock proxy hosts response."""
    return [
        {
            "id": 1,
            "created_on": "2024-01-01T00:00:00Z",
            "modified_on": "2024-01-01T00:00:00Z",
            "owner_user_id": 1,
            "domain_names": ["example.com"],
            "forward_host": "192.168.1.100",
            "forward_port": 8080,
            "forward_scheme": "http",
            "enabled": True,
            "ssl_forced": False,
        }
    ]


class TestNpmClientAuth:
    """Test authentication logic."""

    @pytest.mark.asyncio
    async def test_login_success(self, httpx_mock, mock_token_response):
        """Test successful login."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            result = await client.login()

            assert result.token == "test-jwt-token"
            assert client._token == "test-jwt-token"

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, httpx_mock):
        """Test login with invalid credentials."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            status_code=401,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="wrong",
        ) as client:
            with pytest.raises(NpmAuthenticationError):
                await client.login()

    @pytest.mark.asyncio
    async def test_missing_credentials(self):
        """Test that missing credentials raises error."""
        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="",
            secret="",
        ) as client:
            with pytest.raises(NpmAuthenticationError, match="must be configured"):
                await client.login()


class TestNpmClientEndpoints:
    """Test API endpoint methods."""

    @pytest.mark.asyncio
    async def test_get_proxy_hosts(self, httpx_mock, mock_token_response, mock_proxy_hosts):
        """Test fetching proxy hosts."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/proxy-hosts?expand=owner%2Ccertificate",
            json=mock_proxy_hosts,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            hosts = await client.get_proxy_hosts()

            assert len(hosts) == 1
            assert hosts[0].id == 1
            assert hosts[0].domain_names == ["example.com"]
            assert hosts[0].forward_host == "192.168.1.100"
