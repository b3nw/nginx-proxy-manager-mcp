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
```

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
| `get_system_health` | Check NPM version and status |
| `search_audit_logs` | Query audit log entries |

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
