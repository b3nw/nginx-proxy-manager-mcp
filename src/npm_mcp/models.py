"""Pydantic models for NPM API responses."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    """Response from the login/token endpoint."""

    token: str
    expires: datetime


class UserMeta(BaseModel):
    """User metadata in responses."""

    nickname: str | None = None
    avatar: str | None = None


class Owner(BaseModel):
    """Proxy host owner information."""

    id: int
    created_on: datetime
    modified_on: datetime
    is_disabled: bool
    email: str
    name: str
    nickname: str
    avatar: str
    roles: list[str]


class AccessList(BaseModel):
    """Access list for authentication/IP restrictions."""

    id: int
    created_on: datetime
    modified_on: datetime
    owner_user_id: int = 0
    name: str
    satisfy_any: bool = False
    pass_auth: bool = False


class Certificate(BaseModel):
    """SSL Certificate information."""

    id: int
    created_on: datetime
    modified_on: datetime
    owner_user_id: int
    provider: str
    nice_name: str
    domain_names: list[str]
    expires_on: datetime | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ProxyHostLocation(BaseModel):
    """Custom location configuration for a proxy host."""

    path: str
    forward_host: str | None = None
    forward_port: int | None = None
    forward_scheme: str | None = None
    advanced_config: str = ""


class ProxyHost(BaseModel):
    """Proxy host configuration."""

    id: int
    created_on: datetime
    modified_on: datetime
    owner_user_id: int
    domain_names: list[str]
    forward_host: str
    forward_port: int
    forward_scheme: str = "http"
    certificate_id: int | None = None
    ssl_forced: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    http2_support: bool = False
    block_exploits: bool = False
    caching_enabled: bool = False
    allow_websocket_upgrade: bool = False
    access_list_id: int = 0
    advanced_config: str = ""
    enabled: bool = True
    meta: dict[str, Any] = Field(default_factory=dict)
    locations: list[ProxyHostLocation] = Field(default_factory=list)
    # Optional expanded relations
    owner: Owner | None = None
    certificate: Certificate | None = None


class ProxyHostSummary(BaseModel):
    """Summarized proxy host for list responses."""

    id: int
    domain_names: list[str]
    forward_host: str
    forward_port: int
    forward_scheme: str
    enabled: bool
    ssl_forced: bool
    certificate_id: int | None = None


class HealthStatus(BaseModel):
    """System health/status response."""

    status: str
    version: dict[str, str] | None = None


class Setting(BaseModel):
    """NPM setting entry."""

    id: str
    name: str
    description: str
    value: Any
    meta: dict[str, Any] = Field(default_factory=dict)


class AuditLogEntry(BaseModel):
    """Audit log entry."""

    id: int
    created_on: datetime
    modified_on: datetime
    user_id: int
    object_type: str
    object_id: int
    action: str
    meta: dict[str, Any] = Field(default_factory=dict)
