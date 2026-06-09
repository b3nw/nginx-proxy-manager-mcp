"""Tests for multi-server management and sync tools."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from npm_mcp.models import AccessList, Certificate, HealthStatus, ProxyHost
from npm_mcp.server import (
    clone_proxy_host,
    get_proxy_host_logs,
    list_servers,
    sync_access_lists,
    sync_certificates,
)


@pytest.fixture
def mock_registry():
    """Mock registry with prod and dev servers."""
    reg = MagicMock()
    reg.list_names.return_value = ["prod", "dev"]
    reg.get_default.return_value = "prod"
    return reg


@pytest.mark.asyncio
async def test_list_servers(mock_registry):
    """Test list_servers tool output and health query."""
    client_prod = MagicMock()
    client_prod.get_status = AsyncMock(
        return_value=HealthStatus(status="online", version={"major": "2"})
    )
    client_dev = MagicMock()
    client_dev.get_status = AsyncMock(side_effect=Exception("Connection failed"))

    mock_registry.get.side_effect = lambda name: client_prod if name == "prod" else client_dev

    with patch("npm_mcp.server.get_registry", return_value=mock_registry):
        result_json = await list_servers()
        result = json.loads(result_json)

        assert result["servers"] == ["prod", "dev"]
        assert result["default_server"] == "prod"
        assert result["health"]["prod"]["status"] == "online"
        assert result["health"]["dev"]["status"] == "error"
        assert "Connection failed" in result["health"]["dev"]["error"]


@pytest.mark.asyncio
async def test_clone_proxy_host(mock_registry):
    """Test clone_proxy_host tool with cert and access list resolution."""
    source_client = MagicMock()
    target_client = MagicMock()

    mock_registry.get.side_effect = lambda name: source_client if name == "prod" else target_client

    # Source host setup
    source_host = ProxyHost(
        id=12,
        created_on="2024-01-01T00:00:00Z",
        modified_on="2024-01-01T00:00:00Z",
        owner_user_id=1,
        domain_names=["test.example.com"],
        forward_host="192.168.1.50",
        forward_port=8080,
        forward_scheme="http",
        certificate_id=10,
        access_list_id=5,
        ssl_forced=True,
        hsts_enabled=True,
        hsts_subdomains=False,
        http2_support=True,
        block_exploits=True,
        caching_enabled=False,
        allow_websocket_upgrade=True,
        advanced_config="my advanced config",
        meta={"key": "val"},
    )
    source_client.get_proxy_host = AsyncMock(return_value=source_host)

    # Source dependencies setup
    source_cert = Certificate(
        id=10,
        nice_name="wildcard-example",
        domain_names=["*.example.com"],
        provider="letsencrypt",
    )
    source_client.get_certificate = AsyncMock(return_value=source_cert)

    source_alists = [
        AccessList(
            id=5,
            name="Staging Auth",
            created_on="2024-01-01T00:00:00Z",
            modified_on="2024-01-01T00:00:00Z",
        )
    ]
    source_client.get_access_lists = AsyncMock(return_value=source_alists)

    # Target dependency search results
    target_certs = [
        Certificate(
            id=100,
            nice_name="wildcard-example",
            domain_names=["*.example.com"],
            provider="letsencrypt",
        )
    ]
    target_client.get_certificates = AsyncMock(return_value=target_certs)

    target_alists = [
        AccessList(
            id=500,
            name="Staging Auth",
            created_on="2024-01-02T00:00:00Z",
            modified_on="2024-01-02T00:00:00Z",
        )
    ]
    target_client.get_access_lists = AsyncMock(return_value=target_alists)

    # Mock creation on target
    cloned_host = ProxyHost(
        id=999,
        created_on="2024-01-03T00:00:00Z",
        modified_on="2024-01-03T00:00:00Z",
        owner_user_id=1,
        domain_names=["test.example.com"],
        forward_host="192.168.1.50",
        forward_port=8080,
    )
    target_client.create_proxy_host = AsyncMock(return_value=cloned_host)

    with patch("npm_mcp.server.get_registry", return_value=mock_registry):
        result = await clone_proxy_host(
            source_server="prod",
            target_server="dev",
            host_id=12,
            override_settings={"forward_host": "10.0.0.10"},
        )

        assert "Successfully cloned" in result
        assert "Source Host ID: 12" in result
        assert "Target Host ID: 999" in result
        assert "Resolved to ID 100" in result
        assert "Resolved to ID 500" in result

        target_client.create_proxy_host.assert_called_once_with(
            domain_names=["test.example.com"],
            forward_host="10.0.0.10",  # Overridden!
            forward_port=8080,
            forward_scheme="http",
            certificate_id=100,  # Resolved!
            ssl_forced=True,
            hsts_enabled=True,
            hsts_subdomains=False,
            http2_support=True,
            block_exploits=True,
            caching_enabled=False,
            allow_websocket_upgrade=True,
            access_list_id=500,  # Resolved!
            advanced_config="my advanced config",
            meta={"key": "val"},
        )


@pytest.mark.asyncio
async def test_sync_access_lists(mock_registry):
    """Test sync_access_lists replicates missing access lists with credentials/IPs."""
    source_client = MagicMock()
    target_client = MagicMock()

    mock_registry.get.side_effect = lambda name: source_client if name == "prod" else target_client

    # Source returns raw JSON including items & clients
    source_mock_response = MagicMock()
    source_mock_response.json.return_value = [
        {
            "id": 1,
            "name": "Staging Auth",
            "satisfy_any": False,
            "pass_auth": True,
            "items": [
                {"id": 10, "access_list_id": 1, "username": "u", "password": "p"}
            ],
            "clients": [
                {"id": 20, "access_list_id": 1, "address": "1.1.1.1", "directive": "allow"}
            ],
        },
        {
            "id": 2,
            "name": "Already Synced",
            "satisfy_any": True,
            "pass_auth": False,
        }
    ]
    source_client._request = AsyncMock(return_value=source_mock_response)

    # Target returns raw JSON showing "Already Synced" exists
    target_mock_response = MagicMock()
    target_mock_response.json.return_value = [{"id": 99, "name": "Already Synced"}]
    target_client._request = AsyncMock(return_value=target_mock_response)

    target_client.create_access_list = AsyncMock()

    with patch("npm_mcp.server.get_registry", return_value=mock_registry):
        result = await sync_access_lists(source_server="prod", target_server="dev")

        assert "Created: Staging Auth" in result
        assert "Matched (exists): 'Already Synced' (already exists)" in result

        # Verify items and clients were stripped of database IDs
        target_client.create_access_list.assert_called_once_with(
            name="Staging Auth",
            satisfy_any=False,
            pass_auth=True,
            items=[{"username": "u", "password": "p"}],
            clients=[{"address": "1.1.1.1", "directive": "allow"}],
        )


@pytest.mark.asyncio
async def test_sync_certificates(mock_registry):
    """Test sync_certificates provisions Let's Encrypt and skips custom certs."""
    source_client = MagicMock()
    target_client = MagicMock()

    mock_registry.get.side_effect = lambda name: source_client if name == "prod" else target_client

    # Source certificates
    source_certs = [
        Certificate(
            id=1,
            nice_name="le-cert",
            domain_names=["le.example.com"],
            provider="letsencrypt",
            meta={"letsencrypt_email": "le@test.com", "dns_challenge": True},
        ),
        Certificate(
            id=2,
            nice_name="custom-cert",
            domain_names=["custom.example.com"],
            provider="other-provider",
        ),
        Certificate(
            id=3,
            nice_name="already-on-target",
            domain_names=["existing.example.com"],
            provider="letsencrypt",
        )
    ]
    source_client.get_certificates = AsyncMock(return_value=source_certs)

    # Target certificates
    target_certs = [
        Certificate(
            id=10,
            nice_name="already-on-target",
            domain_names=["existing.example.com"],
            provider="letsencrypt",
        )
    ]
    target_client.get_certificates = AsyncMock(return_value=target_certs)

    target_client.create_certificate = AsyncMock()

    with patch("npm_mcp.server.get_registry", return_value=mock_registry):
        result = await sync_certificates(source_server="prod", target_server="dev")

        assert "Provisioned: 'le.example.com'" in result
        assert "Matched (exists): 'already-on-target'" in result
        assert "Skipped (manual upload required): 'custom-cert'" in result

        target_client.create_certificate.assert_called_once_with(
            domain_names=["le.example.com"],
            email="le@test.com",
            dns_challenge=True,
        )


@pytest.mark.asyncio
async def test_get_proxy_host_logs_api(mock_registry):
    """Test get_proxy_host_logs tool queries the API for logs first."""
    client = MagicMock()
    mock_registry.get.return_value = client

    # Mock host details
    host = ProxyHost(
        id=5,
        created_on="2024-01-01T00:00:00Z",
        modified_on="2024-01-01T00:00:00Z",
        owner_user_id=1,
        domain_names=["test.example.com"],
        forward_host="192.168.1.50",
        forward_port=8080,
    )
    client.get_proxy_host = AsyncMock(return_value=host)

    # Mock API logs endpoint
    client.get_proxy_host_logs = AsyncMock(return_value={
        "lines": ["Log line A", "Log line B", "Filter me out"]
    })

    with patch("npm_mcp.server.get_registry", return_value=mock_registry):
        # Retrieve logs with search filter
        result = await get_proxy_host_logs(
            host_id=5, log_type="access", lines=10, search="Log line"
        )

        assert "test.example.com" in result
        assert "(retrieved via API)" in result
        assert "Log line A" in result
        assert "Log line B" in result
        assert "Filter me out" not in result
        assert "Showing last 2 lines:" in result
