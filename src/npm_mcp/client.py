"""Async HTTP client for Nginx Proxy Manager API."""

import logging
from datetime import UTC, datetime, timedelta

import httpx

from .config import settings
from .exceptions import (
    NpmApiError,
    NpmAuthenticationError,
    NpmConnectionError,
    NpmNotFoundError,
)
from .models import (
    AccessList,
    AuditLogEntry,
    Certificate,
    HealthStatus,
    ProxyHost,
    Setting,
    TokenResponse,
)

logger = logging.getLogger(__name__)


class NpmClient:
    """Async client for interacting with the NPM API."""

    def __init__(
        self,
        base_url: str | None = None,
        identity: str | None = None,
        secret: str | None = None,
        timeout: float = 30.0,
    ):
        """Initialize the NPM client.

        Args:
            base_url: NPM API base URL (defaults to settings)
            identity: NPM user email (defaults to settings)
            secret: NPM user password (defaults to settings)
            timeout: Request timeout in seconds
        """
        self.base_url = (base_url or settings.api_url).rstrip("/")
        self._identity = identity or settings.identity
        self._secret = secret or settings.secret
        self._token: str | None = None
        self._token_expires: datetime | None = None
        self._client = httpx.AsyncClient(timeout=timeout)

    async def __aenter__(self) -> "NpmClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    # -------------------------------------------------------------------------
    # Authentication
    # -------------------------------------------------------------------------

    async def login(self) -> TokenResponse:
        """Authenticate with NPM and obtain a JWT token.

        Returns:
            TokenResponse with token and expiration

        Raises:
            NpmAuthenticationError: If credentials are invalid
            NpmConnectionError: If NPM is unreachable
        """
        if not self._identity or not self._secret:
            raise NpmAuthenticationError("NPM_IDENTITY and NPM_SECRET must be configured")

        try:
            response = await self._client.post(
                f"{self.base_url}/tokens",
                json={"identity": self._identity, "secret": self._secret},
            )
        except httpx.ConnectError as e:
            raise NpmConnectionError(f"Failed to connect to NPM at {self.base_url}: {e}") from e
        except httpx.TimeoutException as e:
            raise NpmConnectionError(f"Connection to NPM timed out: {e}") from e

        if response.status_code == 401:
            raise NpmAuthenticationError("Invalid credentials")

        if response.status_code != 200:
            raise NpmApiError(f"Login failed: {response.text}", status_code=response.status_code)

        data = response.json()
        token_response = TokenResponse(**data)

        self._token = token_response.token
        self._token_expires = token_response.expires

        logger.info("Successfully authenticated with NPM")
        return token_response

    def _is_token_valid(self) -> bool:
        """Check if the current token is still valid (with 1 min buffer)."""
        if not self._token or not self._token_expires:
            return False
        buffer = timedelta(minutes=1)
        return datetime.now(UTC) < (self._token_expires - buffer)

    async def _ensure_authenticated(self) -> None:
        """Ensure we have a valid token, refreshing if needed."""
        if not self._is_token_valid():
            await self.login()

    # -------------------------------------------------------------------------
    # Base Request Handler
    # -------------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an authenticated request to the NPM API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (e.g., "/proxy-hosts")
            **kwargs: Additional arguments passed to httpx

        Returns:
            httpx.Response object

        Raises:
            NpmAuthenticationError: If authentication fails
            NpmConnectionError: If NPM is unreachable
            NpmNotFoundError: If resource not found
            NpmApiError: For other API errors
        """
        await self._ensure_authenticated()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._token}"

        url = f"{self.base_url}{endpoint}"

        try:
            response = await self._client.request(method, url, headers=headers, **kwargs)
        except httpx.ConnectError as e:
            raise NpmConnectionError(f"Failed to connect to NPM: {e}") from e
        except httpx.TimeoutException as e:
            raise NpmConnectionError(f"Request to NPM timed out: {e}") from e

        # Handle 401 - try to re-authenticate once
        if response.status_code == 401:
            logger.info("Token expired, re-authenticating...")
            await self.login()
            headers["Authorization"] = f"Bearer {self._token}"
            response = await self._client.request(method, url, headers=headers, **kwargs)

            if response.status_code == 401:
                raise NpmAuthenticationError("Re-authentication failed")

        # Handle other error responses
        if response.status_code == 404:
            raise NpmNotFoundError(f"Resource not found: {endpoint}")

        if response.status_code >= 400:
            raise NpmApiError(f"API error: {response.text}", status_code=response.status_code)

        return response

    # -------------------------------------------------------------------------
    # API Endpoints
    # -------------------------------------------------------------------------

    async def get_status(self) -> HealthStatus:
        """Get NPM health/status information."""
        # Status endpoint doesn't require auth
        try:
            response = await self._client.get(f"{self.base_url.replace('/api', '')}/")
            return HealthStatus(status="online", version=response.json().get("version"))
        except Exception:
            # Fallback - try authenticated endpoint
            await self._ensure_authenticated()
            return HealthStatus(status="online")

    async def get_proxy_hosts(self, expand: str = "owner,certificate") -> list[ProxyHost]:
        """Get all proxy hosts.

        Args:
            expand: Comma-separated list of relations to expand

        Returns:
            List of ProxyHost objects
        """
        response = await self._request("GET", "/nginx/proxy-hosts", params={"expand": expand})
        data = response.json()
        return [ProxyHost(**host) for host in data]

    async def get_proxy_host(self, host_id: int, expand: str = "owner,certificate") -> ProxyHost:
        """Get a specific proxy host by ID.

        Args:
            host_id: The proxy host ID
            expand: Comma-separated list of relations to expand

        Returns:
            ProxyHost object
        """
        response = await self._request(
            "GET", f"/nginx/proxy-hosts/{host_id}", params={"expand": expand}
        )
        return ProxyHost(**response.json())

    async def get_certificates(self) -> list[Certificate]:
        """Get all SSL certificates."""
        response = await self._request("GET", "/nginx/certificates")
        data = response.json()
        return [Certificate(**cert) for cert in data]

    async def get_certificate(self, cert_id: int) -> Certificate:
        """Get a specific certificate by ID."""
        response = await self._request("GET", f"/nginx/certificates/{cert_id}")
        return Certificate(**response.json())

    async def get_settings(self) -> list[Setting]:
        """Get all NPM settings."""
        response = await self._request("GET", "/settings")
        data = response.json()
        return [Setting(**s) for s in data]

    async def get_audit_log(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """Get audit log entries.

        Args:
            limit: Maximum number of entries to return
            offset: Offset for pagination

        Returns:
            List of AuditLogEntry objects
        """
        response = await self._request(
            "GET",
            "/audit-log",
            params={"limit": limit, "offset": offset},
        )
        data = response.json()
        return [AuditLogEntry(**entry) for entry in data]

    async def get_access_lists(self) -> list[AccessList]:
        """Get all access lists."""
        response = await self._request("GET", "/nginx/access-lists")
        data = response.json()
        return [AccessList(**item) for item in data]

    async def create_proxy_host(
        self,
        domain_names: list[str],
        forward_host: str,
        forward_port: int,
        forward_scheme: str = "http",
        certificate_id: int | None = None,
        ssl_forced: bool = True,
        hsts_enabled: bool = True,
        hsts_subdomains: bool = False,
        http2_support: bool = True,
        block_exploits: bool = True,
        caching_enabled: bool = False,
        allow_websocket_upgrade: bool = True,
        access_list_id: int = 0,
        advanced_config: str = "",
        meta: dict | None = None,
    ) -> ProxyHost:
        """Create a new proxy host.

        Args:
            domain_names: List of domain names for this host
            forward_host: Backend host to forward to
            forward_port: Backend port to forward to
            forward_scheme: http or https
            certificate_id: SSL certificate ID (0 for none, use list_certificates to find)
            ssl_forced: Force SSL/HTTPS
            hsts_enabled: Enable HSTS
            hsts_subdomains: Include subdomains in HSTS
            http2_support: Enable HTTP/2
            block_exploits: Enable exploit blocking
            caching_enabled: Enable caching
            allow_websocket_upgrade: Allow WebSocket upgrades
            access_list_id: Access list ID (0 for none, use list_access_lists to find)
            advanced_config: Custom nginx configuration
            meta: Additional metadata

        Returns:
            Created ProxyHost object
        """
        payload = {
            "domain_names": domain_names,
            "forward_host": forward_host,
            "forward_port": forward_port,
            "forward_scheme": forward_scheme,
            "certificate_id": certificate_id or 0,
            "ssl_forced": ssl_forced,
            "hsts_enabled": hsts_enabled,
            "hsts_subdomains": hsts_subdomains,
            "http2_support": http2_support,
            "block_exploits": block_exploits,
            "caching_enabled": caching_enabled,
            "allow_websocket_upgrade": allow_websocket_upgrade,
            "access_list_id": access_list_id,
            "advanced_config": advanced_config,
            "meta": meta or {},
        }

        response = await self._request("POST", "/nginx/proxy-hosts", json=payload)
        return ProxyHost(**response.json())
