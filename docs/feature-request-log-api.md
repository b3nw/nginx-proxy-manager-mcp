# Feature Request: Per-Host Log Retrieval API

**Project:** [NginxProxyManager/nginx-proxy-manager](https://github.com/NginxProxyManager/nginx-proxy-manager)
**Type:** Feature Request
**Status:** Draft PRD

## Problem Statement

Nginx Proxy Manager writes per-host access and error logs to predictable paths on disk
(`/data/logs/proxy-host-{id}_access.log`, `/data/logs/proxy-host-{id}_error.log`), but
provides no API to read them. The only log-related API is the audit log (`GET /api/audit-log`),
which tracks admin configuration changes — not HTTP traffic.

This means operators and automation tools have no programmatic way to:

- Retrieve recent access log entries for a specific proxy host
- Check error logs when debugging upstream connectivity issues
- Monitor traffic patterns or detect anomalies through the existing API surface

The only workarounds today are direct filesystem access (requiring volume mounts or
`docker exec`) or external log aggregation pipelines, both of which add significant
operational complexity for a task that should be simple.

## Proposed Solution

Add REST API endpoints to retrieve nginx access and error logs for individual proxy hosts.

### New Endpoints

#### `GET /api/nginx/proxy-hosts/{id}/logs`

Retrieve log entries for a specific proxy host.

**Query Parameters:**

| Parameter  | Type   | Default    | Description                                           |
|------------|--------|------------|-------------------------------------------------------|
| `type`     | string | `"access"` | Log type: `"access"` or `"error"`                     |
| `lines`    | int    | `100`      | Number of most recent lines to return (max: `1000`)   |
| `search`   | string | -          | Filter lines containing this substring                |
| `since`    | string | -          | ISO 8601 timestamp — only return lines after this time|

**Response (200):**

```json
{
  "host_id": 5,
  "log_type": "access",
  "file": "proxy-host-5_access.log",
  "total_lines": 4821,
  "returned_lines": 100,
  "lines": [
    "[01/Jun/2025:14:22:31 +0000] HIT 200 200 - GET https app.example.com \"/api/data\" [Client 10.0.0.1] [Length 1542] [Gzip -] [Sent-to 192.168.1.50] \"Mozilla/5.0\" \"https://app.example.com/\"",
    "..."
  ]
}
```

**Error Responses:**

| Status | Condition                           |
|--------|-------------------------------------|
| 404    | Proxy host not found                |
| 404    | Log file does not exist             |
| 403    | User lacks permission for this host |

#### `GET /api/nginx/proxy-hosts/{id}/logs/summary`

Return a statistical summary of recent traffic for a proxy host.

**Response (200):**

```json
{
  "host_id": 5,
  "period": "last_1000_lines",
  "status_codes": {"200": 812, "301": 45, "404": 23, "500": 3},
  "top_paths": ["/api/data", "/", "/login"],
  "top_clients": ["10.0.0.1", "10.0.0.5"],
  "cache_hit_rate": 0.42,
  "access_log_size_bytes": 524288,
  "error_log_size_bytes": 8192
}
```

### Permissions

| Permission         | Description                                |
|--------------------|--------------------------------------------|
| `proxy-hosts:logs` | Read logs for proxy hosts the user can view |

Admin users can read logs for any host. Non-admin users can only read logs
for hosts they own, consistent with existing proxy host permissions.

### Backend Implementation Notes

The implementation is straightforward because log paths are already deterministic
and hardcoded in nginx templates:

```javascript
// backend/templates/proxy_host.conf
access_log /data/logs/proxy-host-{{ id }}_access.log proxy;
error_log /data/logs/proxy-host-{{ id }}_error.log warn;
```

A minimal implementation would:

1. Add a new route in `backend/routes/` (e.g., `proxy-host-logs.js`)
2. Verify the proxy host exists and the user has access
3. Read the last N lines from the log file using a reverse-reader (or `tail`-like approach)
4. Optionally filter lines by substring or timestamp
5. Return as JSON

**Reference files for implementation:**

- `backend/routes/nginx/proxy_hosts.js` — existing proxy host routes and permission model
- `backend/templates/proxy_host.conf` — log path template confirming the naming convention
- `backend/lib/access/` — permission definition files
- `docker/rootfs/etc/logrotate.d/nginx-proxy-manager` — log rotation config (rotated logs
  have `.1`, `.2.gz` suffixes)

### Log Rotation Consideration

NPM rotates logs weekly (access: 4 rotations, error: 10 rotations). The API should
read only the current (unrotated) log file. Rotated archives (`.1`, `.2.gz`) could be
supported in a future iteration but are not required for the initial implementation.

## Motivation

### Use Cases

1. **MCP/AI Agent Integration** — MCP servers wrapping the NPM API (like
   [nginx-proxy-manager-mcp](https://github.com/b3nw/nginx-proxy-manager-mcp)) can
   expose log retrieval to AI assistants for debugging proxy issues conversationally.

2. **Quick Debugging** — When a reverse proxy returns errors, operators need to quickly
   check the access and error logs for that specific host. Today this requires SSH/exec
   access to the container.

3. **Monitoring Dashboards** — Custom dashboards can poll the log endpoint for
   traffic summaries without deploying a full log aggregation stack.

4. **Automation** — CI/CD pipelines and health-check scripts can verify that traffic
   is flowing correctly to newly deployed services behind NPM.

### Why Not External Log Aggregation?

External solutions (Loki, ELK, Fluentd) are powerful but heavy. Many NPM users run
single-host homelab setups where a full log pipeline is disproportionate to the need.
A built-in API covers 80% of use cases with zero additional infrastructure.

## Alternatives Considered

| Approach                  | Pros                        | Cons                                            |
|---------------------------|-----------------------------|-------------------------------------------------|
| **API endpoint (proposed)** | Native, zero extra infra  | Requires upstream PR                            |
| Volume mount + file read  | Works today, no NPM changes | Tight coupling, no access control, not portable |
| Docker exec               | Works today                 | Requires Docker socket, security risk           |
| Sidecar log server        | Decoupled                   | Extra container, extra config, extra maintenance |

## Scope

### In Scope (v1)

- `GET /api/nginx/proxy-hosts/{id}/logs` with `type`, `lines`, `search` params
- Permission checks consistent with existing proxy host access model
- Current (unrotated) log file only

### Out of Scope (Future)

- Log streaming via WebSocket or SSE
- Rotated log archive access (`.gz` files)
- Log summary/analytics endpoint
- Redirection host, dead host, and stream logs (same pattern, easy to add later)
- Log download as file attachment
- Log retention configuration via API
