"""Tests for configuration handling."""

import pytest
from pydantic_settings.exceptions import SettingsError

from npm_mcp.config import DEFAULT_PROXY_SETTINGS, Settings


class TestProxyDefaults:
    """Test NPM_PROXY_DEFAULTS parsing and merging."""

    def test_default_proxy_settings(self):
        """Test that default settings are correct."""
        settings = Settings(identity="test", secret="test")
        defaults = settings.get_proxy_defaults()

        assert defaults["forward_scheme"] == "http"
        assert defaults["certificate_id"] == 0
        assert defaults["ssl_forced"] is True
        assert defaults["block_exploits"] is True
        assert defaults["allow_websocket_upgrade"] is True
        assert defaults["access_list_id"] == 0
        assert defaults["advanced_config"] == ""

    def test_proxy_defaults_json_parsing(self, monkeypatch):
        """Test parsing JSON string from environment variable."""
        monkeypatch.setenv("NPM_IDENTITY", "test")
        monkeypatch.setenv("NPM_SECRET", "test")
        monkeypatch.setenv("NPM_PROXY_DEFAULTS", '{"certificate_id": 24, "ssl_forced": false}')

        settings = Settings()
        defaults = settings.get_proxy_defaults()

        # Overridden values
        assert defaults["certificate_id"] == 24
        assert defaults["ssl_forced"] is False

        # Default values preserved
        assert defaults["forward_scheme"] == "http"
        assert defaults["block_exploits"] is True

    def test_proxy_defaults_dict_passthrough(self):
        """Test that dict values pass through correctly."""
        settings = Settings(
            identity="test",
            secret="test",
            proxy_defaults={"certificate_id": 18, "access_list_id": 5},
        )
        defaults = settings.get_proxy_defaults()

        assert defaults["certificate_id"] == 18
        assert defaults["access_list_id"] == 5

    def test_proxy_defaults_empty_env_raises(self, monkeypatch):
        """Test that empty string env var raises SettingsError."""
        monkeypatch.setenv("NPM_IDENTITY", "test")
        monkeypatch.setenv("NPM_SECRET", "test")
        monkeypatch.setenv("NPM_PROXY_DEFAULTS", "")

        # pydantic-settings tries to JSON decode empty string and fails
        with pytest.raises(SettingsError):
            Settings()

    def test_proxy_defaults_invalid_json_raises(self, monkeypatch):
        """Test that invalid JSON raises SettingsError."""
        monkeypatch.setenv("NPM_IDENTITY", "test")
        monkeypatch.setenv("NPM_SECRET", "test")
        monkeypatch.setenv("NPM_PROXY_DEFAULTS", "{not valid json}")

        # pydantic-settings tries to JSON decode and fails
        with pytest.raises(SettingsError):
            Settings()

    def test_proxy_defaults_merges_not_replaces(self):
        """Test that user defaults merge with base defaults."""
        settings = Settings(
            identity="test",
            secret="test",
            proxy_defaults={"certificate_id": 24},
        )
        defaults = settings.get_proxy_defaults()

        # All keys should be present
        assert set(defaults.keys()) == set(DEFAULT_PROXY_SETTINGS.keys())

        # User value applied
        assert defaults["certificate_id"] == 24

        # Other defaults preserved
        assert defaults["ssl_forced"] is True
        assert defaults["block_exploits"] is True
