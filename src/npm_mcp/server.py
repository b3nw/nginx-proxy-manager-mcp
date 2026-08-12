"""MCP Server implementation for Nginx Proxy Manager."""

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import NpmClient
from .config import NpmInstance, settings
from .exceptions import NpmApiError, NpmAuthenticationError, NpmConnectionError, NpmLogError
from .logs import is_log_dir_configured, list_available_logs, read_log_lines

logger = logging.getLogger(__name__)

_clients: dict[str, NpmClient] = {}


def _get_client(instance: NpmInstance) -> NpmClient:
    """Get or create a client for the given instance."""
    if instance.name not in _clients:
        _clients[instance.name] = NpmClient(
            base_url=instance.api_url,
            identity=instance.identity,
            secret=instance.secret,
        )
    return _clients[instance.name]


def _resolve(instance: str | None) -> tuple[NpmClient, NpmInstance]:
    """Resolve instance name to (client, instance_config). Raises ValueError for bad names."""
    inst = settings.get_instance(instance)
    return _get_client(inst), inst


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Manage client lifecycle."""
    logger.info("NPM MCP Server starting")
    for name in settings.list_instances():
        inst = settings.get_instance(name)
        _clients[name] = NpmClient(
            base_url=inst.api_url, identity=inst.identity, secret=inst.secret
        )
        logger.info(f"  instance '{name}' -> {inst.api_url}")
    try:
        yield
    finally:
        for c in _clients.values():
            await c.close()
        _clients.clear()
        logger.info("NPM MCP Server stopped")


mcp = FastMCP(
    "npm-mcp",
    instructions="MCP server for Nginx Proxy Manager - manage reverse proxy configurations",
    lifespan=lifespan,
    host=settings.mcp_host,
    port=settings.mcp_port,
)


DESTRUCTIVE_DISABLED_MSG = (
    "Destructive operations are disabled. "
    "Set NPM_MCP_ENABLE_DESTRUCTIVE_TOOLS=true to enable."
)


def _check_destructive() -> str | None:
    """Return error message if destructive tools are disabled, else None."""
    if not settings.mcp_enable_destructive_tools:
        return DESTRUCTIVE_DISABLED_MSG
    return None


def _format_error(e: Exception) -> str:
    if isinstance(e, NpmAuthenticationError):
        return f"Authentication failed: {e}"
    elif isinstance(e, NpmConnectionError):
        return f"Connection error: {e}"
    elif isinstance(e, NpmLogError):
        return f"Log error: {e}"
    elif isinstance(e, NpmApiError):
        return f"API error: {e}"
    return f"Error: {e}"


# =============================================================================
# Tools
# =============================================================================


@mcp.tool()
async def list_instances() -> str:
    """List all configured NPM instances.

    Returns the names of all NPM instances available to this MCP server.
    Use these names with the 'instance' parameter on other tools.
    """
    names = settings.list_instances()
    if not names:
        return "No NPM instances configured."
    default = settings.default_instance_name
    lines = []
    for n in names:
        inst = settings.get_instance(n)
        marker = " (default)" if n == default else ""
        lines.append(f"  {n}{marker} -> {inst.api_url}")
    return f"Configured NPM instances ({len(names)}):\n" + "\n".join(lines)


@mcp.tool()
async def list_proxy_hosts(instance: str | None = None) -> str:
    """List all proxy hosts configured in Nginx Proxy Manager.

    Args:
        instance: NPM instance name (omit for default)
    """
    try:
        client, _ = _resolve(instance)
        hosts = await client.get_proxy_hosts()

        if not hosts:
            return "No proxy hosts configured."

        result = []
        for host in hosts:
            domains = ", ".join(host.domain_names)
            ssl_status = "\U0001f512 SSL" if host.ssl_forced else "\U0001f513 HTTP"
            enabled_status = "\u2705" if host.enabled else "\u274c"
            fwd = f"{host.forward_scheme}://{host.forward_host}:{host.forward_port}"
            result.append(
                f"{enabled_status} [{host.id}] {domains}\n"
                f"   \u2192 {fwd} {ssl_status}"
            )

        return f"Found {len(hosts)} proxy host(s):\n\n" + "\n\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def get_proxy_host_details(host_id: int, instance: str | None = None) -> str:
    """Get detailed configuration for a specific proxy host.

    Args:
        host_id: The ID of the proxy host to retrieve
        instance: NPM instance name (omit for default)
    """
    try:
        client, _ = _resolve(instance)
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
async def get_system_health(instance: str | None = None) -> str:
    """Check the health and status of the Nginx Proxy Manager instance.

    Args:
        instance: NPM instance name (omit for default)
    """
    try:
        client, inst = _resolve(instance)
        status = await client.get_status()

        result = [f"Instance: {inst.name}", f"Status: {status.status}"]
        if status.version:
            result.append(f"Version: {status.version}")

        try:
            await client._ensure_authenticated()
            result.append("Authenticated: \u2705")
            try:
                settings_list = await client.get_settings()
                result.append(f"Admin access: \u2705 ({len(settings_list)} settings)")
            except NpmApiError:
                result.append("Admin access: \u274c (limited permissions)")
        except NpmAuthenticationError:
            result.append("Authenticated: \u274c (check credentials)")

        log_dir = inst.log_dir
        if log_dir and is_log_dir_configured(log_dir):
            logs = list_available_logs(log_dir)
            result.append(f"Log directory: \u2705 ({len(logs)} log files found)")
        else:
            result.append(
                "Log directory: \u274c "
                "(not configured \u2014 set NPM_LOG_DIR or instance log_dir)"
            )

        return "\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def search_audit_logs(
    limit: int = 50, offset: int = 0, instance: str | None = None
) -> str:
    """Search the audit log for recent actions in Nginx Proxy Manager.

    Args:
        limit: Maximum number of entries to return (default: 50, max: 100)
        offset: Number of entries to skip for pagination (default: 0)
        instance: NPM instance name (omit for default)
    """
    try:
        client, _ = _resolve(instance)
        limit = min(limit, 100)
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
async def list_certificates(instance: str | None = None) -> str:
    """List all SSL certificates managed by Nginx Proxy Manager.

    Args:
        instance: NPM instance name (omit for default)
    """
    try:
        client, _ = _resolve(instance)
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
async def list_access_lists(instance: str | None = None) -> str:
    """List all access lists configured in Nginx Proxy Manager.

    Args:
        instance: NPM instance name (omit for default)
    """
    try:
        client, _ = _resolve(instance)
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
    instance: str | None = None,
) -> str:
    """Create a new proxy host in Nginx Proxy Manager.

    Args:
        domain_names: List of domain names (e.g., ["app.example.com"])
        forward_host: Backend host/IP to forward to
        forward_port: Backend port to forward to
        forward_scheme: Backend protocol - "http" or "https" (default from config)
        certificate_id: SSL certificate ID (0 for none)
        ssl_forced: Force HTTPS redirect (default from config)
        block_exploits: Enable common exploit blocking (default from config)
        allow_websocket_upgrade: Allow WebSocket connections (default from config)
        access_list_id: Access list ID (0 for no restrictions)
        advanced_config: Custom nginx configuration block
        instance: NPM instance name (omit for default)
    """
    if msg := _check_destructive():
        return msg
    try:
        client, inst = _resolve(instance)
        defaults = inst.get_proxy_defaults()

        def _or(val, key):
            return val if val is not None else defaults[key]

        host = await client.create_proxy_host(
            domain_names=domain_names,
            forward_host=forward_host,
            forward_port=forward_port,
            forward_scheme=_or(forward_scheme, "forward_scheme"),
            certificate_id=_or(certificate_id, "certificate_id"),
            ssl_forced=_or(ssl_forced, "ssl_forced"),
            hsts_enabled=defaults.get("hsts_enabled", True),
            hsts_subdomains=defaults.get("hsts_subdomains", False),
            http2_support=defaults.get("http2_support", True),
            block_exploits=_or(block_exploits, "block_exploits"),
            caching_enabled=defaults.get("caching_enabled", False),
            allow_websocket_upgrade=_or(
                allow_websocket_upgrade, "allow_websocket_upgrade"
            ),
            access_list_id=_or(access_list_id, "access_list_id"),
            advanced_config=_or(advanced_config, "advanced_config"),
            meta=defaults.get("meta", {}),
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


@mcp.tool()
async def update_proxy_host(
    host_id: int,
    forward_host: str | None = None,
    forward_port: int | None = None,
    forward_scheme: str | None = None,
    certificate_id: int | None = None,
    ssl_forced: bool | None = None,
    block_exploits: bool | None = None,
    allow_websocket_upgrade: bool | None = None,
    access_list_id: int | None = None,
    advanced_config: str | None = None,
    instance: str | None = None,
) -> str:
    """Update an existing proxy host in Nginx Proxy Manager.

    Only provided fields will be updated; all others remain unchanged.

    Args:
        host_id: The ID of the proxy host to update
        forward_host: Backend host/IP to forward to
        forward_port: Backend port to forward to
        forward_scheme: Backend protocol - "http" or "https"
        certificate_id: SSL certificate ID (0 for none)
        ssl_forced: Force HTTPS redirect
        block_exploits: Enable common exploit blocking
        allow_websocket_upgrade: Allow WebSocket connections
        access_list_id: Access list ID (0 for no restrictions)
        advanced_config: Custom nginx configuration block
        instance: NPM instance name (omit for default)
    """
    if msg := _check_destructive():
        return msg
    try:
        client, _ = _resolve(instance)
        kwargs = {}
        if forward_host is not None:
            kwargs["forward_host"] = forward_host
        if forward_port is not None:
            kwargs["forward_port"] = forward_port
        if forward_scheme is not None:
            kwargs["forward_scheme"] = forward_scheme
        if certificate_id is not None:
            kwargs["certificate_id"] = certificate_id
        if ssl_forced is not None:
            kwargs["ssl_forced"] = ssl_forced
        if block_exploits is not None:
            kwargs["block_exploits"] = block_exploits
        if allow_websocket_upgrade is not None:
            kwargs["allow_websocket_upgrade"] = allow_websocket_upgrade
        if access_list_id is not None:
            kwargs["access_list_id"] = access_list_id
        if advanced_config is not None:
            kwargs["advanced_config"] = advanced_config

        host = await client.update_proxy_host(host_id, **kwargs)

        domains = ", ".join(host.domain_names)
        return (
            f"Successfully updated proxy host!\n\n"
            f"ID: {host.id}\n"
            f"Domains: {domains}\n"
            f"Forward: {host.forward_scheme}://{host.forward_host}:{host.forward_port}\n"
            f"SSL: {'Enabled' if host.ssl_forced else 'Disabled'}\n"
            f"Certificate ID: {host.certificate_id}"
        )

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def delete_proxy_host(host_id: int, instance: str | None = None) -> str:
    """Delete a proxy host from Nginx Proxy Manager. This cannot be undone.

    Args:
        host_id: The ID of the proxy host to delete
        instance: NPM instance name (omit for default)
    """
    if msg := _check_destructive():
        return msg
    try:
        client, _ = _resolve(instance)
        domains: str | None = None
        try:
            host = await client.get_proxy_host(host_id)
            domains = ", ".join(host.domain_names)
        except Exception:
            pass
        await client.delete_proxy_host(host_id)
        if domains:
            return f"Successfully deleted proxy host [{host_id}] ({domains})."
        return f"Successfully deleted proxy host [{host_id}]."

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def enable_proxy_host(host_id: int, instance: str | None = None) -> str:
    """Enable a proxy host in Nginx Proxy Manager.

    Args:
        host_id: The ID of the proxy host to enable
        instance: NPM instance name (omit for default)
    """
    if msg := _check_destructive():
        return msg
    try:
        client, _ = _resolve(instance)
        await client.enable_proxy_host(host_id)
        try:
            host = await client.get_proxy_host(host_id)
            domains = ", ".join(host.domain_names)
            return f"Successfully enabled proxy host [{host_id}] ({domains})."
        except Exception:
            return f"Successfully enabled proxy host [{host_id}]."

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def disable_proxy_host(host_id: int, instance: str | None = None) -> str:
    """Disable a proxy host in Nginx Proxy Manager without deleting it.

    Args:
        host_id: The ID of the proxy host to disable
        instance: NPM instance name (omit for default)
    """
    if msg := _check_destructive():
        return msg
    try:
        client, _ = _resolve(instance)
        domains: str | None = None
        try:
            host = await client.get_proxy_host(host_id)
            domains = ", ".join(host.domain_names)
        except Exception:
            pass
        await client.disable_proxy_host(host_id)
        if domains:
            return f"Successfully disabled proxy host [{host_id}] ({domains})."
        return f"Successfully disabled proxy host [{host_id}]."

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def get_proxy_host_logs(
    host_id: int,
    log_type: str = "access",
    lines: int = 100,
    search: str | None = None,
    instance: str | None = None,
) -> str:
    """Retrieve recent nginx log entries for a specific proxy host.

    Args:
        host_id: The ID of the proxy host
        log_type: "access" or "error" (default: "access")
        lines: Number of most recent lines (default: 100, max: 500)
        search: Optional case-insensitive filter string
        instance: NPM instance name (omit for default)
    """
    try:
        client, inst = _resolve(instance)
        host = await client.get_proxy_host(host_id)
        domains = ", ".join(host.domain_names)

        log_dir = inst.log_dir
        if not log_dir:
            return (
                "Log directory not configured for this instance. "
                "Set log_dir in the instance config or NPM_LOG_DIR."
            )

        result = read_log_lines(
            host_id=host_id, log_type=log_type, lines=lines, search=search, log_dir=log_dir,
        )

        header_parts = [
            f"Proxy host [{host_id}] {domains} - {log_type} log",
            f"File: {result['file']}",
        ]
        if result["total_lines_in_file"] is not None:
            header_parts.append(f"Total lines in file: {result['total_lines_in_file']}")
        if result["matched_lines"] is not None:
            header_parts.append(f"Lines matching '{search}': {result['matched_lines']}")
        header_parts.append(f"Showing last {result['returned_lines']} lines:")

        header = "\n".join(header_parts)
        if not result["lines"]:
            return f"{header}\n\n(no log entries found)"
        log_output = "\n".join(result["lines"])
        return f"{header}\n\n{log_output}"

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def create_certificate(
    domain_names: list[str],
    email: str,
    dns_challenge: bool = False,
    instance: str | None = None,
) -> str:
    """Provision a new Let's Encrypt SSL certificate.

    Args:
        domain_names: List of domain names for the certificate
        email: Email address for Let's Encrypt notifications
        dns_challenge: Use DNS challenge instead of HTTP (default: False)
        instance: NPM instance name (omit for default)
    """
    if msg := _check_destructive():
        return msg
    try:
        client, _ = _resolve(instance)
        cert = await client.create_certificate(
            domain_names=domain_names, email=email, dns_challenge=dns_challenge,
        )

        domains = ", ".join(cert.domain_names)
        expiry = cert.expires_on.strftime("%Y-%m-%d") if cert.expires_on else "N/A"
        return (
            f"Successfully created certificate!\n\n"
            f"ID: {cert.id}\n"
            f"Provider: {cert.provider}\n"
            f"Domains: {domains}\n"
            f"Expires: {expiry}"
        )

    except Exception as e:
        return _format_error(e)
