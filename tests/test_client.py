"""Tests for NpmClient."""

import json

import pytest

from npm_mcp.client import NpmClient
from npm_mcp.exceptions import NpmApiError, NpmAuthenticationError


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

    @pytest.mark.asyncio
    async def test_api_error_no_double_prefix(self, httpx_mock, mock_token_response):
        """Test that API errors don't have a duplicated 'API error:' prefix."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/proxy-hosts?expand=owner%2Ccertificate",
            json={"error": {"message": "Something went wrong"}},
            status_code=400,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            with pytest.raises(NpmApiError) as exc_info:
                await client.get_proxy_hosts()

            msg = str(exc_info.value)
            assert msg.count("API error") == 0, f"Client should not prefix error: {msg}"


@pytest.fixture
def mock_created_certificate():
    """Mock response for created certificate."""
    return {
        "id": 7,
        "created_on": "2024-01-15T10:00:00Z",
        "modified_on": "2024-01-15T10:00:00Z",
        "owner_user_id": 1,
        "provider": "letsencrypt",
        "nice_name": "app.example.com",
        "domain_names": ["app.example.com"],
        "expires_on": "2024-04-15T10:00:00Z",
        "meta": {"dns_challenge": False},
    }


def _certificate_payload(httpx_mock) -> dict:
    """Return the JSON payload sent to POST /nginx/certificates."""
    requests = [
        r for r in httpx_mock.get_requests(method="POST") if r.url.path == "/api/nginx/certificates"
    ]
    assert len(requests) == 1
    return json.loads(requests[0].content)


class TestNpmClientCertificates:
    """Test certificate creation (issue #17: NPM 2.x meta schema)."""

    @pytest.fixture(autouse=True)
    def _mock_api(self, httpx_mock, mock_token_response, mock_created_certificate):
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/nginx/certificates",
            json=mock_created_certificate,
            status_code=201,
        )

    @staticmethod
    def _client() -> NpmClient:
        return NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        )

    @pytest.mark.asyncio
    async def test_create_certificate_payload(self, httpx_mock):
        """Payload must only contain meta keys accepted by NPM 2.x."""
        async with self._client() as client:
            await client.create_certificate(domain_names=["app.example.com"])

        payload = _certificate_payload(httpx_mock)
        assert payload == {
            "domain_names": ["app.example.com"],
            "meta": {"dns_challenge": False},
            "provider": "letsencrypt",
        }
        assert "letsencrypt_email" not in payload["meta"]
        assert "letsencrypt_agree" not in payload["meta"]

    @pytest.mark.asyncio
    async def test_create_certificate_with_deprecated_email(self, httpx_mock):
        """Deprecated email argument is accepted but never sent."""
        async with self._client() as client:
            await client.create_certificate(
                domain_names=["app.example.com"], email="test@example.com"
            )

        payload = _certificate_payload(httpx_mock)
        assert "letsencrypt_email" not in payload["meta"]
        assert "email" not in payload["meta"]
        assert "letsencrypt_email" not in payload
        assert "email" not in payload
        assert "test@example.com" not in json.dumps(payload)

    @pytest.mark.asyncio
    async def test_create_certificate_dns_challenge(self, httpx_mock):
        """dns_challenge flag is forwarded in meta."""
        async with self._client() as client:
            await client.create_certificate(domain_names=["app.example.com"], dns_challenge=True)

        payload = _certificate_payload(httpx_mock)
        assert payload["meta"] == {"dns_challenge": True}

    @pytest.mark.asyncio
    async def test_create_certificate_response_parsing(self):
        """Response is parsed into a Certificate model."""
        async with self._client() as client:
            cert = await client.create_certificate(domain_names=["app.example.com"])

        assert cert.id == 7
        assert cert.domain_names == ["app.example.com"]
        assert cert.provider == "letsencrypt"
        assert cert.nice_name == "app.example.com"
        assert cert.owner_user_id == 1
        assert cert.expires_on is not None
        assert cert.expires_on.strftime("%Y-%m-%d") == "2024-04-15"
        assert cert.meta == {"dns_challenge": False}
