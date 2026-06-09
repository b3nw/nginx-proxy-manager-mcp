"""MCP Server implementation for Nginx Proxy Manager."""

import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import NpmClient
from .config import settings
from .exceptions import NpmApiError, NpmAuthenticationError, NpmConnectionError, NpmLogError
from .logs import is_log_dir_configured, list_available_logs, read_log_lines

logger = logging.getLogger(__name__)


class ServerRegistry:
    """Manages multiple NpmClient connections."""

    def __init__(self, configs: list[dict[str, Any]], default: str | None = None):
        self._clients: dict[str, NpmClient] = {}
        self._default = default

        # Register multi-server entries
        for cfg in configs:
            name = cfg.get("name")
            url = cfg.get("url") or cfg.get("api_url")
            identity = cfg.get("identity")
            secret = cfg.get("secret")
            if not all([name, url, identity, secret]):
                logger.warning(f"Server '{name}' is missing required fields, skipping")
                continue
            self._clients[name] = NpmClient(base_url=url, identity=identity, secret=secret)

        # Fallback to single-server settings if registry is empty
        if not self._clients and settings.api_url and settings.identity and settings.secret:
            logger.info("No servers in NPM_SERVERS. Using single-server environment variables.")
            self._clients["default"] = NpmClient(
                base_url=settings.api_url,
                identity=settings.identity,
                secret=settings.secret
            )
            if not self._default:
                self._default = "default"

        # Validate default
        if self._default and self._default not in self._clients:
            logger.warning(
                f"Default server '{self._default}' is not in configured servers. "
                "Clearing default."
            )
            self._default = None

    def get(self, name: str | None = None) -> NpmClient:
        """Retrieve client by name. Fallback to default if name is None/empty."""
        if not self._clients:
            raise KeyError("No NPM servers configured.")

        if name is None or name == "":
            if self._default:
                name = self._default
            elif len(self._clients) == 1:
                name = next(iter(self._clients.keys()))
            else:
                raise KeyError("Multiple servers configured but no default server specified.")

        if name not in self._clients:
            raise KeyError(
                f"Server '{name}' not found. "
                f"Configured servers: {list(self._clients.keys())}"
            )
        return self._clients[name]

    def list_names(self) -> list[str]:
        return list(self._clients.keys())

    def get_default(self) -> str | None:
        return self._default

    async def close_all(self) -> None:
        for client in self._clients.values():
            await client.close()


# Global registry
registry: ServerRegistry | None = None


def get_registry() -> ServerRegistry:
    """Get or create the global ServerRegistry instance."""
    global registry
    if registry is None:
        registry = ServerRegistry(settings.servers, settings.default_server)
    return registry


def _get_client(server: str | None = None) -> NpmClient:
    """Retrieve NPM client for the specified server, or fallback to default."""
    return get_registry().get(server)


def get_client() -> NpmClient:
    """Get or create the NPM client instance (backward compatibility)."""
    return _get_client(None)


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Manage client lifecycle."""
    global registry
    registry = ServerRegistry(settings.servers, settings.default_server)
    logger.info(f"NPM MCP Server starting. Configured servers: {registry.list_names()}")
    try:
        yield
    finally:
        if registry:
            await registry.close_all()
            registry = None
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
    if isinstance(e, KeyError):
        return f"Configuration error: {e.args[0]}"
    elif isinstance(e, NpmAuthenticationError):
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
async def list_proxy_hosts(server: str | None = None) -> str:
    """List all proxy hosts configured in Nginx Proxy Manager.

    Returns a summary of all proxy hosts including their domains,
    forward destinations, and SSL status.
    """
    try:
        client = _get_client(server)
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
async def get_proxy_host_details(host_id: int, server: str | None = None) -> str:
    """Get detailed configuration for a specific proxy host.

    Args:
        host_id: The ID of the proxy host to retrieve
        server: Target server name

    Returns full configuration including SSL settings, locations,
    and advanced configuration.
    """
    try:
        client = _get_client(server)
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
async def get_system_health(server: str | None = None) -> str:
    """Check the health and status of the Nginx Proxy Manager instance.

    Returns system status, version information, and connectivity status.
    """
    try:
        client = _get_client(server)
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

        if is_log_dir_configured():
            logs = list_available_logs()
            result.append(f"Log directory: ✅ ({len(logs)} log files found)")
        else:
            result.append(
                "Log directory: ❌ (not configured — set NPM_LOG_DIR to enable get_proxy_host_logs)"
            )

        return "\n".join(result)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def search_audit_logs(limit: int = 50, offset: int = 0, server: str | None = None) -> str:
    """Search the audit log for recent actions in Nginx Proxy Manager.

    Args:
        limit: Maximum number of entries to return (default: 50, max: 100)
        offset: Number of entries to skip for pagination (default: 0)
        server: Target server name

    Returns recent audit log entries showing user actions and changes.
    """
    try:
        client = _get_client(server)
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
async def list_certificates(server: str | None = None) -> str:
    """List all SSL certificates managed by Nginx Proxy Manager.

    Returns a summary of all certificates including their domains,
    provider, and expiration dates.
    """
    try:
        client = _get_client(server)
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
async def list_access_lists(server: str | None = None) -> str:
    """List all access lists configured in Nginx Proxy Manager.

    Returns a summary of all access lists including their IDs and names.
    Use these IDs when creating proxy hosts that require access control.
    """
    try:
        client = _get_client(server)
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
    server: str | None = None,
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
        server: Target server name

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

        client = _get_client(server)
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
            hsts_enabled=defaults.get("hsts_enabled", True),
            hsts_subdomains=defaults.get("hsts_subdomains", False),
            http2_support=defaults.get("http2_support", True),
            block_exploits=block_exploits
            if block_exploits is not None
            else defaults["block_exploits"],
            caching_enabled=defaults.get("caching_enabled", False),
            allow_websocket_upgrade=allow_websocket_upgrade
            if allow_websocket_upgrade is not None
            else defaults["allow_websocket_upgrade"],
            access_list_id=access_list_id
            if access_list_id is not None
            else defaults["access_list_id"],
            advanced_config=advanced_config
            if advanced_config is not None
            else defaults["advanced_config"],
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
    server: str | None = None,
) -> str:
    """Update an existing proxy host in Nginx Proxy Manager.

    Only provided fields will be updated; all others remain unchanged.

    Args:
        host_id: The ID of the proxy host to update
        forward_host: Backend host/IP to forward to
        forward_port: Backend port to forward to
        forward_scheme: Backend protocol - "http" or "https"
        certificate_id: SSL certificate ID (use list_certificates to find, 0 for none)
        ssl_forced: Force HTTPS redirect
        block_exploits: Enable common exploit blocking
        allow_websocket_upgrade: Allow WebSocket connections
        access_list_id: Access list ID (0 for no restrictions)
        advanced_config: Custom nginx configuration block
        server: Target server name

    Returns:
        Details of the updated proxy host.
    """
    try:
        client = _get_client(server)
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
async def get_proxy_host_logs(
    host_id: int,
    log_type: str = "access",
    lines: int = 100,
    search: str | None = None,
    server: str | None = None,
) -> str:
    """Retrieve recent nginx log entries for a specific proxy host.

    Reads the raw nginx access or error log file for the given host or retrieves
    them via the API.

    Args:
        host_id: The ID of the proxy host (use list_proxy_hosts to find IDs)
        log_type: Log type - "access" for HTTP traffic or "error"
            for nginx errors (default: "access")
        lines: Number of most recent lines to return
            (default: 100, max: 500)
        search: Optional filter string - only lines containing this
            text are returned (case-insensitive)
        server: Target server name
    """
    try:
        client = _get_client(server)
        
        # Try retrieving logs via the API first
        try:
            log_data = await client.get_proxy_host_logs(
                host_id=host_id,
                log_type=log_type,
                lines=lines,
            )
            raw_lines = log_data.get("lines", [])
            if search:
                search_lower = search.lower()
                filtered_lines = [
                    line for line in raw_lines if search_lower in line.lower()
                ]
            else:
                filtered_lines = raw_lines

            host = await client.get_proxy_host(host_id)
            domains = ", ".join(host.domain_names)
            header_parts = [
                f"Proxy host [{host_id}] {domains} — {log_type} log (retrieved via API)",
                f"Showing last {len(filtered_lines)} lines:",
            ]
            header = "\n".join(header_parts)
            if not filtered_lines:
                return f"{header}\n\n(no log entries found)"
            return f"{header}\n\n" + "\n".join(filtered_lines)

        except Exception as api_err:
            # Fallback for default server or if local logs are mounted
            reg = get_registry()
            is_default = False
            try:
                target_client = reg.get(server)
                default_client = reg.get(None)
                if target_client.base_url == default_client.base_url:
                    is_default = True
            except Exception:
                pass

            if is_default and is_log_dir_configured():
                host = await client.get_proxy_host(host_id)
                domains = ", ".join(host.domain_names)
                result = read_log_lines(
                    host_id=host_id,
                    log_type=log_type,
                    lines=lines,
                    search=search,
                )
                header_parts = [
                    f"Proxy host [{host_id}] {domains} — {log_type} log (local fallback)",
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
                return f"{header}\n\n" + "\n".join(result["lines"])
            else:
                raise api_err

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def create_certificate(
    domain_names: list[str],
    email: str,
    dns_challenge: bool = False,
    server: str | None = None,
) -> str:
    """Provision a new Let's Encrypt SSL certificate.

    Args:
        domain_names: List of domain names for the certificate
        email: Email address for Let's Encrypt notifications
        dns_challenge: Use DNS challenge instead of HTTP (default: False)
        server: Target server name
    """
    try:
        client = _get_client(server)
        cert = await client.create_certificate(
            domain_names=domain_names,
            email=email,
            dns_challenge=dns_challenge,
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


@mcp.tool()
async def list_servers() -> str:
    """List all configured NPM servers and their health/connectivity status.

    Returns a JSON string containing the list of registered servers,
    the default server, and their health status.
    """
    try:
        reg = get_registry()
        server_names = reg.list_names()
        default_server = reg.get_default()

        health_status = {}
        for name in server_names:
            try:
                client = reg.get(name)
                status = await client.get_status()
                health_status[name] = {"status": status.status, "version": status.version}
            except Exception as e:
                health_status[name] = {"status": "error", "error": str(e)}

        return json.dumps({
            "servers": server_names,
            "default_server": default_server,
            "health": health_status
        }, indent=2)
    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def clone_proxy_host(
    source_server: str,
    target_server: str,
    host_id: int,
    override_settings: dict[str, Any] | None = None,
) -> str:
    """Clone a proxy host configuration from source_server to target_server.

    Resolves certificate and access list IDs automatically by matching names/domains.

    Args:
        source_server: Name of the source server.
        target_server: Name of the destination server.
        host_id: The ID of the host on the source server.
        override_settings: Optional dict of settings to override during creation.
    """
    try:
        source_client = _get_client(source_server)
        target_client = _get_client(target_server)

        # Retrieve host configuration from source server
        host = await source_client.get_proxy_host(host_id)

        # Resolve certificate ID
        target_cert_id = 0
        cert_resolved_msg = "None"
        if host.certificate_id and host.certificate_id > 0:
            try:
                source_cert = await source_client.get_certificate(host.certificate_id)
                target_certs = await target_client.get_certificates()
                
                matched_cert = None
                for cert in target_certs:
                    if (
                        source_cert.nice_name
                        and cert.nice_name
                        and source_cert.nice_name == cert.nice_name
                    ):
                        matched_cert = cert
                        break
                    if (
                        source_cert.domain_names
                        and cert.domain_names
                        and set(source_cert.domain_names) == set(cert.domain_names)
                    ):
                        matched_cert = cert
                        break
                
                if matched_cert:
                    target_cert_id = matched_cert.id
                    cert_name = matched_cert.nice_name or ", ".join(matched_cert.domain_names)
                    cert_resolved_msg = f"Resolved to ID {target_cert_id} ({cert_name})"
                else:
                    source_name = source_cert.nice_name or ", ".join(source_cert.domain_names)
                    cert_resolved_msg = (
                        f"Could not resolve source certificate '{source_name}' "
                        "on target server. Defaulting to None (0)."
                    )
            except Exception as e:
                cert_resolved_msg = f"Error resolving certificate: {e}. Defaulting to None (0)."

        # Resolve access list ID
        target_access_list_id = 0
        access_list_resolved_msg = "None"
        if host.access_list_id and host.access_list_id > 0:
            try:
                source_alists = await source_client.get_access_lists()
                source_alist = next(
                    (al for al in source_alists if al.id == host.access_list_id), None
                )
                
                if source_alist:
                    target_alists = await target_client.get_access_lists()
                    matched_alist = next(
                        (al for al in target_alists if al.name == source_alist.name), None
                    )
                    
                    if matched_alist:
                        target_access_list_id = matched_alist.id
                        access_list_resolved_msg = (
                            f"Resolved to ID {target_access_list_id} ({matched_alist.name})"
                        )
                    else:
                        access_list_resolved_msg = (
                            f"Could not resolve source access list '{source_alist.name}' "
                            "on target server. Defaulting to None (0)."
                        )
                else:
                    access_list_resolved_msg = (
                        "Source access list not found. Defaulting to None (0)."
                    )
            except Exception as e:
                access_list_resolved_msg = (
                    f"Error resolving access list: {e}. Defaulting to None (0)."
                )

        # Construct creation payload
        payload = {
            "domain_names": host.domain_names,
            "forward_host": host.forward_host,
            "forward_port": host.forward_port,
            "forward_scheme": host.forward_scheme,
            "ssl_forced": host.ssl_forced,
            "hsts_enabled": host.hsts_enabled,
            "hsts_subdomains": host.hsts_subdomains,
            "http2_support": host.http2_support,
            "block_exploits": host.block_exploits,
            "caching_enabled": host.caching_enabled,
            "allow_websocket_upgrade": host.allow_websocket_upgrade,
            "advanced_config": host.advanced_config,
            "meta": host.meta,
            "certificate_id": target_cert_id,
            "access_list_id": target_access_list_id,
        }

        # Apply overrides
        if override_settings:
            payload.update(override_settings)

        # Create proxy host on target server
        new_host = await target_client.create_proxy_host(
            domain_names=payload["domain_names"],
            forward_host=payload["forward_host"],
            forward_port=payload["forward_port"],
            forward_scheme=payload["forward_scheme"],
            certificate_id=payload["certificate_id"],
            ssl_forced=payload["ssl_forced"],
            hsts_enabled=payload["hsts_enabled"],
            hsts_subdomains=payload["hsts_subdomains"],
            http2_support=payload["http2_support"],
            block_exploits=payload["block_exploits"],
            caching_enabled=payload["caching_enabled"],
            allow_websocket_upgrade=payload["allow_websocket_upgrade"],
            access_list_id=payload["access_list_id"],
            advanced_config=payload["advanced_config"],
            meta=payload["meta"],
        )

        return (
            f"Successfully cloned proxy host from '{source_server}' to '{target_server}'!\n\n"
            f"Source Host ID: {host_id}\n"
            f"Target Host ID: {new_host.id}\n"
            f"Domains: {', '.join(new_host.domain_names)}\n"
            f"Certificate: {cert_resolved_msg}\n"
            f"Access List: {access_list_resolved_msg}"
        )

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def sync_access_lists(source_server: str, target_server: str) -> str:
    """Sync access lists from source_server to target_server.

    Replicates missing access lists by name, carrying over credentials and IP rules.

    Args:
        source_server: Name of the source server.
        target_server: Name of the target server.
    """
    try:
        source_client = _get_client(source_server)
        target_client = _get_client(target_server)

        # Get raw access lists from both servers to retrieve detailed items and clients
        source_response = await source_client._request("GET", "/nginx/access-lists")
        source_lists = source_response.json()

        target_response = await target_client._request("GET", "/nginx/access-lists")
        target_lists = target_response.json()

        target_names = {al["name"] for al in target_lists}
        
        synced = []
        skipped = []
        
        for al in source_lists:
            name = al.get("name")
            if not name:
                continue
            
            if name in target_names:
                skipped.append(f"'{name}' (already exists)")
                continue

            # Strip database IDs and unique primary keys from items & clients to avoid conflicts
            items = al.get("items", [])
            cleaned_items = []
            for item in items:
                cleaned = item.copy()
                cleaned.pop("id", None)
                cleaned.pop("access_list_id", None)
                cleaned.pop("created_on", None)
                cleaned.pop("modified_on", None)
                cleaned_items.append(cleaned)

            clients = al.get("clients", [])
            cleaned_clients = []
            for client in clients:
                cleaned = client.copy()
                cleaned.pop("id", None)
                cleaned.pop("access_list_id", None)
                cleaned.pop("created_on", None)
                cleaned.pop("modified_on", None)
                cleaned_clients.append(cleaned)

            # Replicate access list
            await target_client.create_access_list(
                name=name,
                satisfy_any=al.get("satisfy_any", False),
                pass_auth=al.get("pass_auth", False),
                items=cleaned_items,
                clients=cleaned_clients,
            )
            synced.append(name)

        result_parts = [f"Synced access lists from '{source_server}' to '{target_server}':"]
        if synced:
            result_parts.append(f"✅ Created: {', '.join(synced)}")
        else:
            result_parts.append("No new access lists were created.")
        if skipped:
            result_parts.append(f"ℹ️ Matched (exists): {', '.join(skipped)}")

        return "\n".join(result_parts)

    except Exception as e:
        return _format_error(e)


@mcp.tool()
async def sync_certificates(source_server: str, target_server: str) -> str:
    """Sync Let's Encrypt certificates from source_server to target_server.

    Matches existing certificates on the target server by domain names.

    Args:
        source_server: Name of the source server.
        target_server: Name of the target server.
    """
    try:
        source_client = _get_client(source_server)
        target_client = _get_client(target_server)

        source_certs = await source_client.get_certificates()
        target_certs = await target_client.get_certificates()

        # Build target domain map for lookup
        target_domains_map = {frozenset(cert.domain_names): cert for cert in target_certs}

        synced = []
        skipped_exists = []
        skipped_custom = []

        for cert in source_certs:
            domains = cert.domain_names
            if not domains:
                continue

            cert_domains_set = frozenset(domains)
            
            # Check if matching cert exists on target
            if cert_domains_set in target_domains_map:
                skipped_exists.append(f"'{cert.nice_name or ', '.join(domains)}'")
                continue

            # Check provider type
            if cert.provider != "letsencrypt":
                skipped_custom.append(
                    f"'{cert.nice_name or ', '.join(domains)}' "
                    f"(custom provider: {cert.provider})"
                )
                continue

            # Re-provision Let's Encrypt certificate
            email = (
                cert.meta.get("letsencrypt_email")
                or cert.meta.get("email")
                or settings.identity
                or "admin@example.com"
            )
            dns_challenge = cert.meta.get("dns_challenge", False)

            await target_client.create_certificate(
                domain_names=domains,
                email=email,
                dns_challenge=dns_challenge,
            )
            synced.append(f"'{', '.join(domains)}'")

        result_parts = [
            f"Synced Let's Encrypt certificates from '{source_server}' "
            f"to '{target_server}':"
        ]
        if synced:
            result_parts.append(f"✅ Provisioned: {', '.join(synced)}")
        else:
            result_parts.append("No new certificates were provisioned.")
        if skipped_exists:
            result_parts.append(f"ℹ️ Matched (exists): {', '.join(skipped_exists)}")
        if skipped_custom:
            result_parts.append(f"⚠️ Skipped (manual upload required): {', '.join(skipped_custom)}")

        return "\n".join(result_parts)

    except Exception as e:
        return _format_error(e)
