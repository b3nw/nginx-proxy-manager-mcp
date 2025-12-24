"""Configuration management using pydantic-settings."""

from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Default values for proxy host creation
DEFAULT_PROXY_SETTINGS: dict[str, Any] = {
    "forward_scheme": "http",
    "certificate_id": 0,
    "ssl_forced": True,
    "hsts_enabled": True,
    "hsts_subdomains": False,
    "http2_support": True,
    "caching_enabled": False,
    "block_exploits": True,
    "allow_websocket_upgrade": True,
    "access_list_id": 0,
    "advanced_config": "",
    "meta": {},
}


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="NPM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # NPM API Configuration
    api_url: str = "http://localhost:81/api"
    identity: str = ""
    secret: str = ""

    # MCP Server Configuration
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_transport: str = "stdio"  # "stdio" or "http"

    # Proxy host creation defaults (JSON string)
    # Example: '{"certificate_id": 24, "ssl_forced": true}'
    proxy_defaults: dict[str, Any] = {}

    @field_validator("proxy_defaults", mode="before")
    @classmethod
    def parse_proxy_defaults(cls, v: Any) -> dict[str, Any]:
        """Parse JSON string to dict, or pass through if already dict."""
        if isinstance(v, dict):
            return v
        if isinstance(v, str) and v.strip():
            import json

            try:
                return json.loads(v)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in NPM_PROXY_DEFAULTS: {e}") from e
        return {}

    def get_proxy_defaults(self) -> dict[str, Any]:
        """Get merged proxy defaults (base defaults + user overrides)."""
        merged = DEFAULT_PROXY_SETTINGS.copy()
        merged.update(self.proxy_defaults)
        return merged


settings = Settings()
