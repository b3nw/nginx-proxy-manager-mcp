"""Configuration management using pydantic-settings."""

import json as _json
from typing import Any

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

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


class NpmInstance:
    """Connection details for a single NPM instance."""

    __slots__ = ("name", "api_url", "identity", "secret", "log_dir", "proxy_defaults")

    def __init__(
        self,
        name: str,
        api_url: str,
        identity: str,
        secret: str,
        log_dir: str = "",
        proxy_defaults: dict[str, Any] | None = None,
    ):
        self.name = name
        self.api_url = api_url.rstrip("/")
        self.identity = identity
        self.secret = secret
        self.log_dir = log_dir
        self.proxy_defaults = proxy_defaults or {}

    def get_proxy_defaults(self) -> dict[str, Any]:
        merged = DEFAULT_PROXY_SETTINGS.copy()
        merged.update(self.proxy_defaults)
        return merged


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="NPM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        arbitrary_types_allowed=True,
    )

    api_url: str = "http://localhost:81/api"
    identity: str = ""
    secret: str = ""
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 8000
    mcp_transport: str = "stdio"

    # Runtime guard for destructive/write operations
    mcp_enable_destructive_tools: bool = False

    # Optional bearer token for authenticating MCP clients over HTTP
    mcp_auth_token: str = ""
    log_dir: str = ""
    proxy_defaults: dict[str, Any] = {}
    instances: dict[str, dict[str, Any]] = {}

    # ponytail: runtime cache, not pydantic fields
    _instances_parsed: dict[str, NpmInstance] = {}
    _default_instance_name: str = ""

    @field_validator("proxy_defaults", mode="before")
    @classmethod
    def parse_proxy_defaults(cls, v: Any) -> dict[str, Any]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str) and v.strip():
            try:
                return _json.loads(v)
            except _json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in NPM_PROXY_DEFAULTS: {e}") from e
        return {}

    @field_validator("instances", mode="before")
    @classmethod
    def parse_instances(cls, v: Any) -> dict[str, dict[str, Any]]:
        if isinstance(v, dict):
            return v
        if isinstance(v, str) and v.strip():
            try:
                return _json.loads(v)
            except _json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in NPM_INSTANCES: {e}") from e
        return {}

    @model_validator(mode="after")
    def build_instances(self) -> "Settings":
        parsed: dict[str, NpmInstance] = {}
        if self.instances:
            for name, cfg in self.instances.items():
                if not isinstance(cfg, dict):
                    raise ValueError(
                        f"NPM_INSTANCES['{name}'] must be an object, "
                        f"got {type(cfg).__name__}"
                    )
                missing = [
                    k for k in ("api_url", "identity", "secret") if not cfg.get(k)
                ]
                if missing:
                    raise ValueError(
                        f"NPM_INSTANCES['{name}'] missing required field(s): "
                        f"{missing}"
                    )
                for field in ("api_url", "identity", "secret"):
                    val = cfg[field]
                    if not isinstance(val, str):
                        raise ValueError(
                            f"NPM_INSTANCES['{name}']['{field}'] must be a string, "
                            f"got {type(val).__name__}"
                        )
                log_dir = cfg.get("log_dir", "")
                if not isinstance(log_dir, str):
                    raise ValueError(
                        f"NPM_INSTANCES['{name}']['log_dir'] must be a string, "
                        f"got {type(log_dir).__name__}"
                    )
                proxy_defaults = cfg.get("proxy_defaults", {})
                if not isinstance(proxy_defaults, dict):
                    raise ValueError(
                        f"NPM_INSTANCES['{name}']['proxy_defaults'] must be an object, "
                        f"got {type(proxy_defaults).__name__}"
                    )
                parsed[name] = NpmInstance(
                    name=name,
                    api_url=cfg["api_url"],
                    identity=cfg["identity"],
                    secret=cfg["secret"],
                    log_dir=log_dir,
                    proxy_defaults=proxy_defaults,
                )
            self._default_instance_name = next(iter(parsed))
        elif self.identity and self.secret:
            parsed["default"] = NpmInstance(
                name="default",
                api_url=self.api_url,
                identity=self.identity,
                secret=self.secret,
                log_dir=self.log_dir,
                proxy_defaults=self.proxy_defaults,
            )
            self._default_instance_name = "default"
        self._instances_parsed = parsed
        return self

    def get_proxy_defaults(self) -> dict[str, Any]:
        merged = DEFAULT_PROXY_SETTINGS.copy()
        merged.update(self.proxy_defaults)
        return merged

    def get_instance(self, name: str | None = None) -> NpmInstance:
        if not self._instances_parsed:
            raise ValueError(
                "No NPM instances configured. Set NPM_IDENTITY/NPM_SECRET or NPM_INSTANCES."
            )
        key = name or self._default_instance_name
        if key not in self._instances_parsed:
            available = ", ".join(self._instances_parsed)
            raise ValueError(f"Unknown instance '{key}'. Available: {available}")
        return self._instances_parsed[key]

    @property
    def default_instance_name(self) -> str:
        return self._default_instance_name

    def list_instances(self) -> list[str]:
        return list(self._instances_parsed.keys())


settings = Settings()
