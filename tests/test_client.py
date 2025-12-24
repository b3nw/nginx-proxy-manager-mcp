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


@pytest.fixture
def mock_access_lists():
    """Mock access lists response."""
    return [
        {
            "id": 1,
            "created_on": "2024-01-01T00:00:00Z",
            "modified_on": "2024-01-01T00:00:00Z",
            "owner_user_id": 1,
            "name": "Admin Only",
            "satisfy_any": False,
            "pass_auth": True,
        },
        {
            "id": 2,
            "created_on": "2024-01-02T00:00:00Z",
            "modified_on": "2024-01-02T00:00:00Z",
            "owner_user_id": 1,
            "name": "Internal Network",
            "satisfy_any": True,
            "pass_auth": False,
        },
    ]


@pytest.fixture
def mock_created_proxy_host():
    """Mock response for created proxy host."""
    return {
        "id": 42,
        "created_on": "2024-01-15T10:00:00Z",
        "modified_on": "2024-01-15T10:00:00Z",
        "owner_user_id": 1,
        "domain_names": ["newapp.example.com"],
        "forward_host": "10.0.0.50",
        "forward_port": 3000,
        "forward_scheme": "http",
        "enabled": True,
        "ssl_forced": True,
        "certificate_id": 24,
        "block_exploits": True,
        "allow_websocket_upgrade": True,
        "access_list_id": 0,
        "advanced_config": "",
    }


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

    @pytest.mark.asyncio
    async def test_get_access_lists(self, httpx_mock, mock_token_response, mock_access_lists):
        """Test fetching access lists."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/access-lists",
            json=mock_access_lists,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            access_lists = await client.get_access_lists()

            assert len(access_lists) == 2
            assert access_lists[0].id == 1
            assert access_lists[0].name == "Admin Only"
            assert access_lists[0].pass_auth is True
            assert access_lists[1].id == 2
            assert access_lists[1].name == "Internal Network"
            assert access_lists[1].satisfy_any is True

    @pytest.mark.asyncio
    async def test_create_proxy_host(
        self, httpx_mock, mock_token_response, mock_created_proxy_host
    ):
        """Test creating a proxy host."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/nginx/proxy-hosts",
            json=mock_created_proxy_host,
            status_code=201,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            host = await client.create_proxy_host(
                domain_names=["newapp.example.com"],
                forward_host="10.0.0.50",
                forward_port=3000,
                certificate_id=24,
                ssl_forced=True,
            )

            assert host.id == 42
            assert host.domain_names == ["newapp.example.com"]
            assert host.forward_host == "10.0.0.50"
            assert host.forward_port == 3000
            assert host.ssl_forced is True
            assert host.certificate_id == 24
