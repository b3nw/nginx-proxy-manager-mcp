"""Entry point for npm-mcp server."""

import argparse
import logging
import sys

from .config import settings


def setup_logging() -> None:
    """Configure logging for the server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    """Main entry point for the MCP server."""
    parser = argparse.ArgumentParser(description="NPM MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=settings.mcp_transport,
        help="Transport mode (default: from NPM_MCP_TRANSPORT env or 'stdio')",
    )
    parser.add_argument(
        "--host",
        default=settings.mcp_host,
        help="Host for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.mcp_port,
        help="Port for HTTP transport (default: 8000)",
    )
    args = parser.parse_args()

    setup_logging()
    logger = logging.getLogger(__name__)

    # Import server here to avoid circular imports
    from .server import mcp

    if args.transport == "stdio":
        logger.info("Starting MCP server in stdio mode")
        mcp.run(transport="stdio")
    else:
        logger.info(f"Starting MCP server in HTTP mode on {args.host}:{args.port}")

        # Always construct the HTTP app using the same FastMCP.http_app()
        # so that its lifespan (StreamableHTTPSessionManager background task) runs correctly.
        app = mcp.http_app()

        # Mount /health directly on the inner router
        from starlette.responses import PlainTextResponse
        from starlette.routing import Route
        app.router.routes.insert(0, Route("/health", lambda r: PlainTextResponse("ok")))

        if settings.mcp_auth_token:
            logger.info("Bearer token authentication enabled")
            from .auth import BearerAuthMiddleware
            app.add_middleware(BearerAuthMiddleware, token=settings.mcp_auth_token)

        import uvicorn

        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()

