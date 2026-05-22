"""Log file reader for Nginx Proxy Manager proxy host logs."""

from __future__ import annotations

import re
from pathlib import Path

from .config import settings
from .exceptions import NpmLogError

LOG_FILE_PATTERN = re.compile(r"^proxy-host-(\d+)_(access|error)\.log$")

MAX_LINES = 500
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB safety cap


def _get_log_dir() -> Path:
    """Resolve and validate the configured log directory."""
    log_dir = settings.log_dir
    if not log_dir:
        raise NpmLogError(
            "NPM_LOG_DIR is not configured. Mount NPM's /data/logs volume "
            "and set NPM_LOG_DIR to the mount path. See README for details."
        )
    path = Path(log_dir)
    if not path.is_dir():
        raise NpmLogError(f"Log directory does not exist: {log_dir}")
    return path


def _log_file_path(host_id: int, log_type: str) -> Path:
    if log_type not in ("access", "error"):
        raise NpmLogError(f"Invalid log type: {log_type!r} (must be 'access' or 'error')")
    log_dir = _get_log_dir()
    return log_dir / f"proxy-host-{host_id}_{log_type}.log"


def read_log_lines(
    host_id: int,
    log_type: str = "access",
    lines: int = 100,
    search: str | None = None,
) -> dict:
    """Read the last N lines from a proxy host log file.

    Args:
        host_id: NPM proxy host ID.
        log_type: "access" or "error".
        lines: Number of most recent lines to return (capped at MAX_LINES).
        search: Optional substring filter applied to each line.

    Returns:
        Dict with host_id, log_type, file name, line count, and the lines themselves.
    """
    lines = max(1, min(lines, MAX_LINES))
    log_path = _log_file_path(host_id, log_type)

    if not log_path.is_file():
        raise NpmLogError(
            f"Log file not found: {log_path.name}. "
            "The proxy host may not have received any traffic yet, "
            "or the log directory mount is incorrect."
        )

    file_size = log_path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise NpmLogError(
            f"Log file is too large ({file_size / 1024 / 1024:.1f} MB). "
            "Consider using an external log aggregation tool."
        )

    all_lines = log_path.read_text(errors="replace").splitlines()
    total_lines = len(all_lines)

    if search:
        search_lower = search.lower()
        all_lines = [line for line in all_lines if search_lower in line.lower()]

    tail = all_lines[-lines:]

    return {
        "host_id": host_id,
        "log_type": log_type,
        "file": log_path.name,
        "total_lines_in_file": total_lines if not search else None,
        "matched_lines": len(all_lines) if search else None,
        "returned_lines": len(tail),
        "lines": tail,
    }


def is_log_dir_configured() -> bool:
    """Check whether the log directory is configured and accessible."""
    if not settings.log_dir:
        return False
    return Path(settings.log_dir).is_dir()


def list_available_logs() -> list[dict]:
    """List all proxy-host log files present in the log directory.

    Returns:
        List of dicts with host_id, log_type, file name, and size.
    """
    log_dir = _get_log_dir()
    results = []
    for entry in sorted(log_dir.iterdir()):
        match = LOG_FILE_PATTERN.match(entry.name)
        if match and entry.is_file():
            results.append(
                {
                    "host_id": int(match.group(1)),
                    "log_type": match.group(2),
                    "file": entry.name,
                    "size_bytes": entry.stat().st_size,
                }
            )
    return results
