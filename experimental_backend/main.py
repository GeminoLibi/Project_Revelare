#!/usr/bin/env python3
"""
Project Revelare - Experimental Backend
Main entry point for the modernized API server.
"""

import uvicorn
import logging
from pathlib import Path

from src.config import config


def main() -> None:
    """Main entry point for the Revelare API server."""

    # Set up logging
    logging.basicConfig(
        level=getattr(logging, config.settings.LOG_LEVEL),
        format=config.settings.LOG_FORMAT
    )

    logger = logging.getLogger(__name__)
    logger.info("Starting Project Revelare Experimental Backend...")

    # Print startup information
    print("🚀 Project Revelare API Server")
    print("=" * 40)
    print(f"Version: {config.settings.VERSION}")
    print(f"Host: {config.settings.HOST}")
    print(f"Port: {config.settings.PORT}")
    print(f"Debug: {config.settings.DEBUG}")
    print(f"Environment: {'Development' if config.settings.DEBUG else 'Production'}")
    print(f"API Docs: http://localhost:{config.settings.PORT}/docs")
    print(f"Health Check: http://localhost:{config.settings.PORT}/health")
    print("=" * 40)

    # Start the server
    uvicorn.run(
        "src.api.app:app",
        host=config.settings.HOST,
        port=config.settings.PORT,
        reload=config.settings.DEBUG,
        log_level=config.settings.LOG_LEVEL.lower(),
        access_log=True,
        server_header=False,  # Don't expose server info
    )


if __name__ == "__main__":
    main()
