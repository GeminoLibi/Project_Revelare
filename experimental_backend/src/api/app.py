"""
Main FastAPI Application
Comprehensive API application with security, middleware, and error handling.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator, Dict, Any
import logging

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from ..config import config
from ..database.session import get_db
from ..utils.auth import auth_service, jwt_manager
from ..utils.logging import setup_logging
from .middleware.security import SecurityMiddleware
from .middleware.request_logging import RequestLoggingMiddleware
from .middleware.error_handling import ErrorHandlingMiddleware


# Rate limiter
limiter = Limiter(key_func=get_remote_address)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager."""
    # Startup
    logger = logging.getLogger(__name__)
    logger.info("Starting Project Revelare API...")

    # Initialize logging
    setup_logging()

    # Validate configuration
    try:
        config.validate_configuration()
        logger.info("Configuration validation passed")
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise

    # Database connectivity check
    try:
        # Test database connection
        db = next(get_db())
        db.close()
        logger.info("Database connection established")
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise

    logger.info(f"API server starting on {config.settings.HOST}:{config.settings.PORT}")
    yield

    # Shutdown
    logger.info("Shutting down Project Revelare API...")


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""

    # Create FastAPI app
    app = FastAPI(
        title=config.settings.PROJECT_NAME,
        description=config.settings.PROJECT_DESCRIPTION,
        version=config.settings.VERSION,
        openapi_url=f"{config.settings.API_V1_STR}/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Add rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Add middleware
    app.add_middleware(SlowAPIMiddleware)

    # CORS middleware
    if config.is_production():
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.get_cors_origins(),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
            ],
        )
    else:
        # Development: allow all origins
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Security middleware
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(ErrorHandlingMiddleware)

    # Compression middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Trusted host middleware (production only)
    if config.is_production():
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Configure appropriately for production
        )

    return app


# Create the application instance
app = create_application()


# Global exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions with consistent response format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "type": "http_exception",
                "message": exc.detail,
                "status_code": exc.status_code,
            }
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle general exceptions with proper logging."""
    logger = logging.getLogger(__name__)
    logger.error(f"Unhandled exception: {exc}", exc_info=True)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "type": "internal_server_error",
                "message": "An unexpected error occurred",
                "status_code": 500,
            }
        },
    )


# Health check endpoint
@app.get("/health", tags=["health"])
@limiter.limit("10/minute")
async def health_check(request: Request) -> Dict[str, Any]:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": config.settings.VERSION,
        "environment": "production" if config.is_production() else "development",
    }


# Root endpoint
@app.get("/", tags=["root"])
@limiter.limit("30/minute")
async def root(request: Request) -> Dict[str, Any]:
    """Root endpoint with API information."""
    return {
        "name": config.settings.PROJECT_NAME,
        "description": config.settings.PROJECT_DESCRIPTION,
        "version": config.settings.VERSION,
        "docs_url": "/docs",
        "health_url": "/health",
        "api_base": config.settings.API_V1_STR,
    }


# API info endpoint
@app.get("/api", tags=["api"])
@limiter.limit("30/minute")
async def api_info(request: Request) -> Dict[str, Any]:
    """API information and capabilities."""
    return {
        "api_version": config.settings.VERSION,
        "api_prefix": config.settings.API_V1_STR,
        "supported_formats": ["application/json"],
        "authentication": "JWT Bearer token",
        "features": [
            "user_management",
            "case_management",
            "evidence_processing",
            "analysis_reporting",
            "file_upload",
            "real_time_processing"
        ],
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": config.settings.RATE_LIMIT_REQUESTS,
            "window_seconds": config.settings.RATE_LIMIT_WINDOW,
        },
        "security": {
            "cors_enabled": True,
            "https_enforced": config.is_production(),
            "mfa_supported": True,
            "audit_logging": True,
        }
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=config.settings.HOST,
        port=config.settings.PORT,
        reload=config.settings.DEBUG,
        log_level=config.settings.LOG_LEVEL.lower(),
        access_log=True,
    )
