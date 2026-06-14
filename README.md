# NPM MCP Server

MCP server for [Nginx Proxy Manager](https://nginxproxymanager.com/) - manage your reverse proxy through AI assistants.

## Quick Start (Docker)

The easiest way to run the NPM MCP server - no cloning required!

```bash
# Download the compose file
curl -O https://raw.githubusercontent.com/b3nw/nginx-proxy-manager-mcp/main/compose.yaml

# Edit the environment variables, then start
docker compose up -d
```

Or run directly:

```bash
docker run -d \
  --name npm-mcp \
  -p 8000:8000 \
  -e NPM_API_URL=http://your-npm:81/api \
  -e NPM_IDENTITY=admin@example.com \
  -e NPM_SECRET=yourpassword \
  -e NPM_MCP_TRANSPORT=http \
  ghcr.io/b3nw/nginx-proxy-manager-mcp:latest
```

## Installation (Local)

```bash
# Using uv (recommended)
uv pip install -e .

# Or with pip
pip install -e .
```

## Configuration

Copy `env.example` to `.env` and configure:

```env
NPM_API_URL=http://your-npm-instance:81/api
NPM_IDENTITY=admin@example.com
NPM_SECRET=yourpassword

# Optional: Server settings
NPM_MCP_PORT=8000
NPM_MCP_TRANSPORT=stdio  # or "http"

# Optional: Default values for create_proxy_host (JSON)
NPM_PROXY_DEFAULTS='{"certificate_id": 24, "ssl_forced": true}'
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NPM_API_URL` | Yes | `http://localhost:81/api` | NPM API endpoint |
| `NPM_IDENTITY` | Yes | - | NPM user email |
| `NPM_SECRET` | Yes | - | NPM user password |
| `NPM_MCP_HOST` | No | `0.0.0.0` | MCP server bind address |
| `NPM_MCP_PORT` | No | `8000` | MCP server port |
| `NPM_MCP_TRANSPORT` | No | `stdio` | Transport mode (`stdio` or `http`) |
| `NPM_LOG_DIR` | No | - | Path to mounted NPM log directory (enables `get_proxy_host_logs`) |
| `NPM_PROXY_DEFAULTS` | No | `{}` | JSON defaults for `create_proxy_host` |

### NPM_PROXY_DEFAULTS Keys

Configure default values for proxy host creation:

```bash
NPM_PROXY_DEFAULTS='{"certificate_id": 24, "ssl_forced": true, "block_exploits": true}'
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `forward_scheme` | string | `"http"` | Backend protocol (`http` or `https`) |
| `certificate_id` | int | `0` | SSL certificate ID (use `list_certificates` to find) |
| `ssl_forced` | bool | `true` | Force HTTPS redirect |
| `block_exploits` | bool | `true` | Enable common exploit blocking |
| `allow_websocket_upgrade` | bool | `true` | Allow WebSocket connections |
| `access_list_id` | int | `0` | Access list ID (use `list_access_lists` to find) |
| `advanced_config` | string | `""` | Custom nginx configuration block |

## Usage

### Stdio Mode (for Claude Desktop, etc.)

```bash
npm-mcp
# or
python -m npm_mcp.main --transport stdio
```

### HTTP Mode (for remote agents)

```bash
npm-mcp --transport http
# Starts server on http://0.0.0.0:8000
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "npm": {
      "command": "npm-mcp",
      "env": {
        "NPM_API_URL": "http://localhost:81/api",
        "NPM_IDENTITY": "admin@example.com",
        "NPM_SECRET": "yourpassword"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_proxy_hosts` | List all proxy hosts |
| `get_proxy_host_details` | Get full config for a specific host |
| `get_proxy_host_logs` | Retrieve nginx access/error logs for a proxy host (requires log mount) |
| `get_system_health` | Check NPM version and status |
| `search_audit_logs` | Query audit log entries |
| `list_certificates` | List SSL certificates |
| `list_access_lists` | List access lists for authentication/IP restrictions |
| `create_proxy_host` | Create a new proxy host |
| `update_proxy_host` | Update an existing proxy host (v0.0.3+) |
| `delete_proxy_host` | Delete a proxy host permanently |
| `enable_proxy_host` | Enable (bring online) a disabled proxy host |
| `disable_proxy_host` | Disable (take offline) a proxy host without deleting it |
| `create_certificate` | Provision a new Let's Encrypt SSL certificate (v0.0.3+) |

## Managing Proxy Host Lifecycle

Beyond creating and updating hosts, the server can delete a host outright or
toggle a host on and off without losing its configuration. Find the host ID
with `list_proxy_hosts` first.

```text
# Take a host offline temporarily (config is preserved)
disable_proxy_host(42)

# Bring it back online
enable_proxy_host(42)

# Permanently remove a host (cannot be undone)
delete_proxy_host(42)
```

Notes:

- `enable_proxy_host` / `disable_proxy_host` map to NPM's
  `POST /nginx/proxy-hosts/{id}/enable` and `/disable` endpoints. If the host
  is already in the requested state, NPM returns an HTTP 400 error
  (e.g. `Host is already enabled`), which the tool surfaces as an API error.
- `delete_proxy_host` maps to `DELETE /nginx/proxy-hosts/{id}` and is
  destructive — the reverse proxy stops serving the host's domains
  immediately. Recreate it with `create_proxy_host` if you need it back.

## Log Access Setup

The `get_proxy_host_logs` tool reads nginx log files directly from disk. Since NPM has no API for log retrieval, you need to mount NPM's log directory into the MCP container.

NPM writes per-host logs to `/data/logs/` inside its container:
- `proxy-host-{id}_access.log` — HTTP request log (client IP, status, path, user agent)
- `proxy-host-{id}_error.log` — nginx error log (upstream failures, config issues)

### Docker Compose (same stack)

If NPM and the MCP server share a compose stack with a named volume:

```yaml
services:
  nginx-proxy-manager:
    image: jc21/nginx-proxy-manager:latest
    volumes:
      - npm_data:/data

  npm-mcp:
    image: ghcr.io/b3nw/nginx-proxy-manager-mcp:latest
    environment:
      - NPM_API_URL=http://nginx-proxy-manager:81/api
      - NPM_IDENTITY=admin@example.com
      - NPM_SECRET=yourpassword
      - NPM_LOG_DIR=/data/npm-logs
    volumes:
      # Mount NPM's /data volume — logs are in /data/logs/ inside it
      - npm_data:/data/npm-logs:ro
    depends_on:
      - nginx-proxy-manager

volumes:
  npm_data:
```

> **Note:** NPM stores logs under `/data/logs/` inside its data volume. When you
> mount the full `/data` volume to `/data/npm-logs`, the MCP server looks for logs at
> `/data/npm-logs/logs/`. Set `NPM_LOG_DIR` to match your mount path plus `/logs`.

If you mounted the full data volume:

```bash
NPM_LOG_DIR=/data/npm-logs/logs
```

### Bind Mount (separate stacks)

If NPM uses a bind mount (e.g., `./npm-data:/data`), mount the logs subdirectory directly:

```yaml
npm-mcp:
  volumes:
    - /path/to/npm-data/logs:/data/npm-logs:ro
  environment:
    - NPM_LOG_DIR=/data/npm-logs
```

### Docker Run

```bash
docker run -d \
  --name npm-mcp \
  -p 8000:8000 \
  -v npm_data:/data/npm-logs:ro \
  -e NPM_API_URL=http://your-npm:81/api \
  -e NPM_IDENTITY=admin@example.com \
  -e NPM_SECRET=yourpassword \
  -e NPM_LOG_DIR=/data/npm-logs/logs \
  -e NPM_MCP_TRANSPORT=http \
  ghcr.io/b3nw/nginx-proxy-manager-mcp:latest
```

### Local Development (non-Docker)

Point `NPM_LOG_DIR` at wherever NPM's logs are on your filesystem:

```bash
NPM_LOG_DIR=/path/to/npm/data/logs npm-mcp
```

### Verifying the Mount

After starting, call `get_system_health` — if the log directory is mounted and accessible
the tool will confirm it. You can also call `get_proxy_host_logs` with any host ID to
verify logs are readable.

## Development

```bash
# Install with dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/
```

## License

MIT
