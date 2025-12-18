"""Configuration management using pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


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


settings = Settings()
