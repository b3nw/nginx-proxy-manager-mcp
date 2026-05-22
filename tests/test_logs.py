"""Tests for the log reader module."""

import pytest

from npm_mcp.exceptions import NpmLogError
from npm_mcp.logs import (
    is_log_dir_configured,
    list_available_logs,
    read_log_lines,
)

SAMPLE_ACCESS_LOG = (
    '[22/May/2025:10:00:01 +0000] - 200 200 - GET https app.example.com'
    ' "/" [Client 10.0.0.1] [Length 1542] "Mozilla/5.0" "-"\n'
    '[22/May/2025:10:00:02 +0000] - 301 301 - GET http app.example.com'
    ' "/old-path" [Client 10.0.0.2] [Length 0] "curl/7.88" "-"\n'
    '[22/May/2025:10:00:03 +0000] - 404 404 - GET https app.example.com'
    ' "/missing" [Client 10.0.0.1] [Length 548] "Mozilla/5.0" "-"\n'
    '[22/May/2025:10:00:04 +0000] - 200 200 - POST https app.example.com'
    ' "/api/data" [Client 10.0.0.3] [Length 256] "python-requests/2.31" "-"\n'
    '[22/May/2025:10:00:05 +0000] - 502 502 - GET https app.example.com'
    ' "/health" [Client 10.0.0.1] [Length 166] "kube-probe/1.28" "-"\n'
)

SAMPLE_ERROR_LOG = (
    "2025/05/22 10:00:05 [error] 42#42: *123 connect() failed"
    " (111: Connection refused) while connecting to upstream,"
    " client: 10.0.0.1, server: app.example.com\n"
)


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    """Create a temp log directory with sample log files."""
    logs = tmp_path / "logs"
    logs.mkdir()

    (logs / "proxy-host-5_access.log").write_text(SAMPLE_ACCESS_LOG)
    (logs / "proxy-host-5_error.log").write_text(SAMPLE_ERROR_LOG)
    (logs / "proxy-host-12_access.log").write_text("")
    (logs / "fallback_error.log").write_text("global error\n")

    monkeypatch.setattr("npm_mcp.logs.settings.log_dir", str(logs))
    return logs


@pytest.fixture
def no_log_dir(monkeypatch):
    """Ensure log_dir is unconfigured."""
    monkeypatch.setattr("npm_mcp.logs.settings.log_dir", "")


class TestReadLogLines:
    def test_read_access_log(self, log_dir):
        result = read_log_lines(host_id=5, log_type="access")
        assert result["host_id"] == 5
        assert result["log_type"] == "access"
        assert result["file"] == "proxy-host-5_access.log"
        assert result["returned_lines"] == 5
        assert result["total_lines_in_file"] == 5
        assert "app.example.com" in result["lines"][0]

    def test_read_error_log(self, log_dir):
        result = read_log_lines(host_id=5, log_type="error")
        assert result["log_type"] == "error"
        assert result["returned_lines"] == 1
        assert "Connection refused" in result["lines"][0]

    def test_lines_limit(self, log_dir):
        result = read_log_lines(host_id=5, log_type="access", lines=2)
        assert result["returned_lines"] == 2
        assert "10:00:04" in result["lines"][0]
        assert "10:00:05" in result["lines"][1]

    def test_lines_capped_at_max(self, log_dir):
        result = read_log_lines(host_id=5, log_type="access", lines=9999)
        assert result["returned_lines"] == 5

    def test_search_filter(self, log_dir):
        result = read_log_lines(host_id=5, log_type="access", search="404")
        assert result["returned_lines"] == 1
        assert result["matched_lines"] == 1
        assert result["total_lines_in_file"] is None
        assert "/missing" in result["lines"][0]

    def test_search_case_insensitive(self, log_dir):
        result = read_log_lines(host_id=5, log_type="access", search="MOZILLA")
        assert result["returned_lines"] == 2

    def test_search_by_ip(self, log_dir):
        result = read_log_lines(host_id=5, log_type="access", search="10.0.0.1")
        assert result["returned_lines"] == 3

    def test_nonexistent_host(self, log_dir):
        with pytest.raises(NpmLogError, match="Log file not found"):
            read_log_lines(host_id=999, log_type="access")

    def test_empty_log_file(self, log_dir):
        with pytest.raises(NpmLogError, match="Log file not found"):
            read_log_lines(host_id=12, log_type="error")

    def test_invalid_log_type(self, log_dir):
        with pytest.raises(NpmLogError, match="Invalid log type"):
            read_log_lines(host_id=5, log_type="combined")

    def test_no_log_dir_configured(self, no_log_dir):
        with pytest.raises(NpmLogError, match="NPM_LOG_DIR is not configured"):
            read_log_lines(host_id=5, log_type="access")

    def test_nonexistent_log_dir(self, monkeypatch):
        monkeypatch.setattr("npm_mcp.logs.settings.log_dir", "/nonexistent/path")
        with pytest.raises(NpmLogError, match="does not exist"):
            read_log_lines(host_id=5, log_type="access")


class TestIsLogDirConfigured:
    def test_configured(self, log_dir):
        assert is_log_dir_configured() is True

    def test_not_configured(self, no_log_dir):
        assert is_log_dir_configured() is False

    def test_configured_but_missing(self, monkeypatch):
        monkeypatch.setattr("npm_mcp.logs.settings.log_dir", "/nonexistent")
        assert is_log_dir_configured() is False


class TestListAvailableLogs:
    def test_lists_proxy_host_logs_only(self, log_dir):
        results = list_available_logs()
        files = {r["file"] for r in results}
        assert "proxy-host-5_access.log" in files
        assert "proxy-host-5_error.log" in files
        assert "proxy-host-12_access.log" in files
        assert "fallback_error.log" not in files

    def test_correct_metadata(self, log_dir):
        results = list_available_logs()
        access_5 = next(r for r in results if r["file"] == "proxy-host-5_access.log")
        assert access_5["host_id"] == 5
        assert access_5["log_type"] == "access"
        assert access_5["size_bytes"] > 0

    def test_not_configured(self, no_log_dir):
        with pytest.raises(NpmLogError, match="NPM_LOG_DIR is not configured"):
            list_available_logs()
