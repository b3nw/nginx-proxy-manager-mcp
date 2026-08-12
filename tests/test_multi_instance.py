"""Tests for multi-instance configuration."""

import pytest

from npm_mcp.config import Settings


class TestMultiInstance:
    def test_single_instance_legacy(self):
        """Legacy single-instance config creates a 'default' instance."""
        s = Settings(api_url="http://npm:81/api", identity="a@b", secret="x")
        assert s.list_instances() == ["default"]
        inst = s.get_instance()
        assert inst.api_url == "http://npm:81/api"
        assert inst.identity == "a@b"

    def test_multi_instance_from_dict(self):
        s = Settings(
            identity="ignored", secret="ignored",
            instances={
                "prod": {"api_url": "http://prod:81/api", "identity": "a@b", "secret": "p"},
                "staging": {"api_url": "http://staging:81/api", "identity": "c@d", "secret": "s"},
            },
        )
        assert set(s.list_instances()) == {"prod", "staging"}
        assert s.get_instance("prod").api_url == "http://prod:81/api"
        assert s.get_instance("staging").identity == "c@d"

    def test_default_instance_is_first(self):
        s = Settings(
            identity="i", secret="s",
            instances={
                "alpha": {"api_url": "http://a:81/api", "identity": "x", "secret": "y"},
                "beta": {"api_url": "http://b:81/api", "identity": "x", "secret": "y"},
            },
        )
        default = s.get_instance()
        assert default.name == "alpha"

    def test_unknown_instance_raises(self):
        s = Settings(identity="a", secret="b")
        with pytest.raises(ValueError, match="Unknown instance"):
            s.get_instance("nonexistent")

    def test_no_instances_raises(self):
        s = Settings(identity="", secret="")
        with pytest.raises(ValueError, match="No NPM instances configured"):
            s.get_instance()

    def test_instance_proxy_defaults(self):
        s = Settings(
            identity="i", secret="s",
            instances={
                "prod": {
                    "api_url": "http://p:81/api",
                    "identity": "x",
                    "secret": "y",
                    "proxy_defaults": {"certificate_id": 42},
                },
            },
        )
        defaults = s.get_instance("prod").get_proxy_defaults()
        assert defaults["certificate_id"] == 42
        assert defaults["ssl_forced"] is True  # base default preserved

    def test_instances_json_env(self, monkeypatch):
        monkeypatch.setenv("NPM_IDENTITY", "x")
        monkeypatch.setenv("NPM_SECRET", "y")
        monkeypatch.setenv(
            "NPM_INSTANCES",
            '{"site1":{"api_url":"http://s1:81/api","identity":"a","secret":"b"}}',
        )
        s = Settings()
        assert s.list_instances() == ["site1"]

    def test_missing_required_field_raises(self):
        with pytest.raises(ValueError, match="missing required field"):
            Settings(
                identity="i", secret="s",
                instances={"bad": {"identity": "a", "secret": "b"}},
            )

    def test_default_instance_name_property(self):
        s = Settings(identity="a", secret="b")
        assert s.default_instance_name == "default"
