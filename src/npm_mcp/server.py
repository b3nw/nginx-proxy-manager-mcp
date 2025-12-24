"""MCP Server implementation for Nginx Proxy Manager."""

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import NpmClient
from .config import settings
from .exceptions import NpmApiError, NpmAuthenticationError, NpmConnectionError

logger = logging.getLogger(__name__)

# Create global client instance (lazy initialization)
_client: NpmClient | None = None


def get_client() -> NpmClient:
    """Get or create the NPM client instance."""
    global _client
    if _client is None:
        _client = NpmClient()
    return _client


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Manage client lifecycle."""
    global _client
    _client = NpmClient()
    logger.info(f"NPM MCP Server starting, connecting to {settings.api_url}")
    try:
        yield
    finally:
        if _client:
            await _client.close()
            _client = None
        logger.info("NPM MCP Server stopped")


# Initialize FastMCP server
mcp = FastMCP(
    "npm-mcp",
    instructions="MCP server for Nginx Proxy Manager - manage reverse proxy configurations",
    lifespan=lifespan,
    host=settings.mcp_host,
    port=settings.mcp_port,
)


def _format_error(e: Exception) -> str:
    """Format exception for tool response."""
    if isinstance(e, NpmAuthenticationError):
        return f"Authentication failed: {e}"
    elif isinstance(e, NpmConnectionError):
        return f"Connection error: {e}"
    elif isinstance(e, NpmApiError):
        return f"API error: {e}"
    return f"Error: {e}"


# =============================================================================
# Tools
# =============================================================================


@mcp.tool()
async def list_proxy_hosts() -> str:
    """List all proxy hosts configured in Nginx Proxy Manager.

    Returns a summary of all proxy hosts including their domains,
    forward destinations, and SSL status.
    """
    try:
        client = get_client()
        hosts = await client.get_proxy_hosts()

        if not hosts:
            return "No proxy hosts configured."

        result = []
        for host in hosts:
            domains = ", ".join(host.domain_names)
            ssl_status = "🔒 SSL" if host.ssl_forced else "🔓 HTTP"
            enabled_status = "✅" if host.enabled else "❌"

            result.append(
                f"{enabled_status} [{host.id}] {domains}\n"
                f"   → {host.forward_scheme}://{host.forward_host}:{host.forward_port} {ssl_status}"
            )

        return f"Found {len(hosts)} proxy host(s):\n\n" + "\n\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def get_proxy_host_details(host_id: int) -> str:
    """Get detailed configuration for a specific proxy host.

    Args:
        host_id: The ID of the proxy host to retrieve

    Returns full configuration including SSL settings, locations,
    and advanced configuration.
    """
    try:
        client = get_client()
        host = await client.get_proxy_host(host_id)

        details: dict[str, Any] = {
            "id": host.id,
            "domains": host.domain_names,
            "forward": {
                "scheme": host.forward_scheme,
                "host": host.forward_host,
                "port": host.forward_port,
            },
            "enabled": host.enabled,
            "ssl": {
                "forced": host.ssl_forced,
                "certificate_id": host.certificate_id,
                "hsts_enabled": host.hsts_enabled,
                "http2_support": host.http2_support,
            },
            "security": {
                "block_exploits": host.block_exploits,
                "access_list_id": host.access_list_id,
            },
            "performance": {
                "caching_enabled": host.caching_enabled,
                "allow_websocket_upgrade": host.allow_websocket_upgrade,
            },
            "created_on": host.created_on.isoformat(),
            "modified_on": host.modified_on.isoformat(),
        }

        if host.advanced_config:
            details["advanced_config"] = host.advanced_config

        if host.locations:
            details["locations"] = [
                {
                    "path": loc.path,
                    "forward_host": loc.forward_host,
                    "forward_port": loc.forward_port,
                }
                for loc in host.locations
            ]

        if host.owner:
            details["owner"] = host.owner.name

        return json.dumps(details, indent=2)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def get_system_health() -> str:
    """Check the health and status of the Nginx Proxy Manager instance.

    Returns system status, version information, and connectivity status.
    """
    try:
        client = get_client()
        status = await client.get_status()

        result = [f"Status: {status.status}"]

        if status.version:
            result.append(f"Version: {status.version}")

        # Test authentication by getting proxy hosts (lower permission requirement)
        try:
            await client._ensure_authenticated()
            result.append("Authenticated: ✅")

            # Try to get settings (admin only)
            try:
                settings_list = await client.get_settings()
                result.append(f"Admin access: ✅ ({len(settings_list)} settings)")
            except NpmApiError:
                result.append("Admin access: ❌ (limited permissions)")
        except NpmAuthenticationError:
            result.append("Authenticated: ❌ (check credentials)")

        return "\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def search_audit_logs(limit: int = 50, offset: int = 0) -> str:
    """Search the audit log for recent actions in Nginx Proxy Manager.

    Args:
        limit: Maximum number of entries to return (default: 50, max: 100)
        offset: Number of entries to skip for pagination (default: 0)

    Returns recent audit log entries showing user actions and changes.
    """
    try:
        client = get_client()
        limit = min(limit, 100)  # Cap at 100
        entries = await client.get_audit_log(limit=limit, offset=offset)

        if not entries:
            return "No audit log entries found."

        result = []
        for entry in entries:
            timestamp = entry.created_on.strftime("%Y-%m-%d %H:%M:%S")
            result.append(
                f"[{timestamp}] User {entry.user_id}: "
                f"{entry.action} {entry.object_type} #{entry.object_id}"
            )

        header = f"Audit log entries ({len(entries)} of {limit} requested, offset {offset}):\n"
        return header + "\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def list_certificates() -> str:
    """List all SSL certificates managed by Nginx Proxy Manager.

    Returns a summary of all certificates including their domains,
    provider, and expiration dates.
    """
    try:
        client = get_client()
        certs = await client.get_certificates()

        if not certs:
            return "No certificates configured."

        result = []
        for cert in certs:
            domains = ", ".join(cert.domain_names[:3])
            if len(cert.domain_names) > 3:
                domains += f" (+{len(cert.domain_names) - 3} more)"

            expiry = ""
            if cert.expires_on:
                expiry = f" (expires: {cert.expires_on.strftime('%Y-%m-%d')})"

            result.append(
                f"[{cert.id}] {cert.nice_name} ({cert.provider})\n   Domains: {domains}{expiry}"
            )

        return f"Found {len(certs)} certificate(s):\n\n" + "\n\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def list_access_lists() -> str:
    """List all access lists configured in Nginx Proxy Manager.

    Returns a summary of all access lists including their IDs and names.
    Use these IDs when creating proxy hosts that require access control.
    """
    try:
        client = get_client()
        access_lists = await client.get_access_lists()

        if not access_lists:
            return "No access lists configured."

        result = []
        for al in access_lists:
            result.append(f"[{al.id}] {al.name}")

        return f"Found {len(access_lists)} access list(s):\n\n" + "\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def create_proxy_host(
    domain_names: list[str],
    forward_host: str,
    forward_port: int,
    forward_scheme: str | None = None,
    certificate_id: int | None = None,
    ssl_forced: bool | None = None,
    block_exploits: bool | None = None,
    allow_websocket_upgrade: bool | None = None,
    access_list_id: int | None = None,
    advanced_config: str | None = None,
) -> str:
    """Create a new proxy host in Nginx Proxy Manager.

    Args:
        domain_names: List of domain names (e.g., ["app.ext.ben.io"])
        forward_host: Backend host/IP to forward to (e.g., "192.168.1.100" or "container-name")
        forward_port: Backend port to forward to (e.g., 8080)
        forward_scheme: Backend protocol - "http" or "https" (default from config)
        certificate_id: SSL certificate ID. Use list_certificates to find available certs.
                       Use 0 for no SSL, or the ID of a wildcard cert. (default from config)
        ssl_forced: Force HTTPS redirect (default from config)
        block_exploits: Enable common exploit blocking (default from config)
        allow_websocket_upgrade: Allow WebSocket connections (default from config)
        access_list_id: Access list ID for authentication. Use list_access_lists to find.
                       Use 0 for no access restrictions. (default from config)
        advanced_config: Custom nginx configuration block (default from config)

    Returns:
        Details of the created proxy host including the new host ID.

    Note:
        Default values can be configured via NPM_PROXY_DEFAULTS environment variable.
        Example: NPM_PROXY_DEFAULTS='{"certificate_id": 24, "ssl_forced": true}'

    Example:
        create_proxy_host(
            domain_names=["myapp.ext.ben.io"],
            forward_host="10.0.0.50",
            forward_port=3000,
            certificate_id=24,  # *.ext.ben.io wildcard
        )
    """
    try:
        # Get defaults from config, then override with provided values
        defaults = settings.get_proxy_defaults()

        client = get_client()
        host = await client.create_proxy_host(
            domain_names=domain_names,
            forward_host=forward_host,
            forward_port=forward_port,
            forward_scheme=forward_scheme
            if forward_scheme is not None
            else defaults["forward_scheme"],
            certificate_id=certificate_id
            if certificate_id is not None
            else defaults["certificate_id"],
            ssl_forced=ssl_forced if ssl_forced is not None else defaults["ssl_forced"],
            block_exploits=block_exploits
            if block_exploits is not None
            else defaults["block_exploits"],
            allow_websocket_upgrade=allow_websocket_upgrade
            if allow_websocket_upgrade is not None
            else defaults["allow_websocket_upgrade"],
            access_list_id=access_list_id
            if access_list_id is not None
            else defaults["access_list_id"],
            advanced_config=advanced_config
            if advanced_config is not None
            else defaults["advanced_config"],
        )

        domains = ", ".join(host.domain_names)
        return (
            f"Successfully created proxy host!\n\n"
            f"ID: {host.id}\n"
            f"Domains: {domains}\n"
            f"Forward: {host.forward_scheme}://{host.forward_host}:{host.forward_port}\n"
            f"SSL: {'Enabled' if host.ssl_forced else 'Disabled'}"
        )

    except Exception as e:
        return _format_error(e)
