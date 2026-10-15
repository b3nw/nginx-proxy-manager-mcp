"""Tests for NpmClient."""

import json

import pytest
from httpx import Response

from npm_mcp.client import NpmClient
from npm_mcp.exceptions import NpmApiError, NpmAuthenticationError, NpmConnectionError


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


MOCK_HOST_WITH_LOCATIONS = {
    "id": 7,
    "created_on": "2024-01-01T00:00:00Z",
    "modified_on": "2024-01-01T00:00:00Z",
    "owner_user_id": 1,
    "domain_names": ["app.example.com"],
    "forward_host": "192.168.1.100",
    "forward_port": 8080,
    "forward_scheme": "http",
    "enabled": True,
    "ssl_forced": False,
    "advanced_config": "",
    # No ``access_list_id`` on locations — the field is omitted when unset.
    "locations": [
        {
            "path": "/",
            "forward_scheme": "http",
            "forward_host": "192.168.1.100",
            "forward_port": 8080,
            "advanced_config": "auth_request /guard;\n",
        },
        {
            "path": "/api",
            "forward_scheme": "http",
            "forward_host": "192.168.1.100",
            "forward_port": 8080,
            "forward_path": "/api",
            "advanced_config": "",
        },
    ],
}


def _api_request_body(httpx_mock, method):
    """Return the parsed JSON body of the last API request with a method.

    Filters by method because the login POST is also recorded.
    """

    requests = httpx_mock.get_requests(method=method)
    api_requests = [r for r in requests if "/tokens" not in str(r.url)]
    assert api_requests, f"no {method} API request recorded"
    return json.loads(api_requests[-1].content)


class TestProxyHostLocations:
    """Test custom locations support on proxy hosts."""

    @pytest.mark.asyncio
    async def test_location_model_parses_all_fields(self, httpx_mock, mock_token_response):
        """Location model keeps forward_path and access_list_id."""
        from npm_mcp.models import ProxyHost

        host = ProxyHost(**MOCK_HOST_WITH_LOCATIONS)
        assert host.locations is not None and len(host.locations) == 2
        assert host.locations[0].advanced_config == "auth_request /guard;\n"
        assert host.locations[1].forward_path == "/api"
        # Absent access_list_id defaults to None, not 0.
        assert host.locations[1].access_list_id is None

        host_with_acl = ProxyHost(
            **{
                **MOCK_HOST_WITH_LOCATIONS,
                "locations": [{**MOCK_HOST_WITH_LOCATIONS["locations"][0], "access_list_id": 5}],
            }
        )
        assert host_with_acl.locations is not None
        assert host_with_acl.locations[0].access_list_id == 5

    @pytest.mark.asyncio
    async def test_create_with_locations(
        self, httpx_mock, mock_token_response, mock_created_proxy_host
    ):
        """Create sends the locations list in the POST body."""

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

        locations = [
            {
                "path": "/api",
                "forward_scheme": "http",
                "forward_host": "10.0.0.50",
                "forward_port": 3000,
                "forward_path": "/api",
                "advanced_config": "",
                "access_list_id": 0,
            }
        ]

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            await client.create_proxy_host(
                domain_names=["newapp.example.com"],
                forward_host="10.0.0.50",
                forward_port=3000,
                locations=locations,
            )

            assert _api_request_body(httpx_mock, "POST")["locations"] == locations

    @pytest.mark.asyncio
    async def test_create_without_locations_omits_key(
        self, httpx_mock, mock_token_response, mock_created_proxy_host
    ):
        """Create without locations must not send the key at all."""

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
            await client.create_proxy_host(
                domain_names=["newapp.example.com"],
                forward_host="10.0.0.50",
                forward_port=3000,
            )

            assert "locations" not in _api_request_body(httpx_mock, "POST")

    @pytest.mark.asyncio
    async def test_update_preserves_locations_when_omitted(
        self, httpx_mock, mock_token_response
    ):
        """Update without locations must re-send the existing list (no drop)."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/proxy-hosts/7?expand=owner%2Ccertificate",
            json=MOCK_HOST_WITH_LOCATIONS,
        )
        httpx_mock.add_response(
            method="PUT",
            url="http://localhost:81/api/nginx/proxy-hosts/7",
            json=MOCK_HOST_WITH_LOCATIONS,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            await client.update_proxy_host(7, forward_port=9090)

            body = _api_request_body(httpx_mock, "PUT")
            assert body["forward_port"] == 9090
            assert body["locations"] == MOCK_HOST_WITH_LOCATIONS["locations"]
            # The preserved payload must not inject access_list_id when unset.
            for loc in body["locations"]:
                assert "access_list_id" not in loc

    @pytest.mark.asyncio
    async def test_update_replaces_locations_when_provided(
        self, httpx_mock, mock_token_response
    ):
        """An explicit locations list replaces the existing one entirely."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/proxy-hosts/7?expand=owner%2Ccertificate",
            json=MOCK_HOST_WITH_LOCATIONS,
        )
        httpx_mock.add_response(
            method="PUT",
            url="http://localhost:81/api/nginx/proxy-hosts/7",
            json=MOCK_HOST_WITH_LOCATIONS,
        )

        replacement = [
            {
                "path": "/new",
                "forward_scheme": "http",
                "forward_host": "192.168.1.200",
                "forward_port": 9000,
                "advanced_config": "",
                "access_list_id": 0,
            }
        ]

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            await client.update_proxy_host(7, locations=replacement)

            body = _api_request_body(httpx_mock, "PUT")
            assert body["locations"] == replacement

    @pytest.mark.asyncio
    async def test_update_preserves_access_list_id_when_set(self, httpx_mock, mock_token_response):
        """Preserved locations keep an explicitly set access_list_id."""
        host_with_acl = {
            **MOCK_HOST_WITH_LOCATIONS,
            "locations": [
                {**MOCK_HOST_WITH_LOCATIONS["locations"][0], "access_list_id": 5}
            ],
        }
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/proxy-hosts/7?expand=owner%2Ccertificate",
            json=host_with_acl,
        )
        httpx_mock.add_response(
            method="PUT",
            url="http://localhost:81/api/nginx/proxy-hosts/7",
            json=host_with_acl,
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            await client.update_proxy_host(7, forward_port=9090)

            body = _api_request_body(httpx_mock, "PUT")
            assert body["locations"][0]["access_list_id"] == 5

    @pytest.mark.asyncio
    async def test_update_empty_locations_clears_list(self, httpx_mock, mock_token_response):
        """Passing locations=[] sends an empty list to clear existing ones."""
        httpx_mock.add_response(
            method="POST",
            url="http://localhost:81/api/tokens",
            json=mock_token_response,
        )
        httpx_mock.add_response(
            method="GET",
            url="http://localhost:81/api/nginx/proxy-hosts/7?expand=owner%2Ccertificate",
            json=MOCK_HOST_WITH_LOCATIONS,
        )
        httpx_mock.add_response(
            method="PUT",
            url="http://localhost:81/api/nginx/proxy-hosts/7",
            json={**MOCK_HOST_WITH_LOCATIONS, "locations": []},
        )

        async with NpmClient(
            base_url="http://localhost:81/api",
            identity="test@test.com",
            secret="password",
        ) as client:
            await client.update_proxy_host(7, locations=[])

            body = _api_request_body(httpx_mock, "PUT")
            assert body["locations"] == []
