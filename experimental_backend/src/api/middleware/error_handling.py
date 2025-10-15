"""
Error Handling Middleware
Centralized error handling and response formatting.
"""

import logging
import traceback
from typing import Dict, Any

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


logger = logging.getLogger(__name__)


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for consistent error handling and response formatting."""

    async def dispatch(self, request: Request, call_next):
        """Handle errors and format responses consistently."""

        try:
            response = await call_next(request)
            return response

        except HTTPException as exc:
            # Handle FastAPI HTTP exceptions
            return self._format_http_exception(request, exc)

        except Exception as exc:
            # Handle unexpected exceptions
            return self._handle_unexpected_error(request, exc)

    def _format_http_exception(self, request: Request, exc: HTTPException) -> JSONResponse:
        """Format HTTP exceptions consistently."""

        # Log the exception
        logger.warning(
            f"HTTP exception in {request.method} {request.url.path}: {exc.detail}",
            extra={
                "request_id": getattr(request.state, "request_id", "unknown"),
                "status_code": exc.status_code,
                "detail": exc.detail,
                "event_type": "http_exception"
            }
        )

        # Return consistent error response
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "type": "http_exception",
                    "message": exc.detail,
                    "status_code": exc.status_code,
                    "path": request.url.path,
                    "method": request.method,
                }
            },
        )

    def _handle_unexpected_error(self, request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions with proper logging."""

        # Generate a unique error ID for tracking
        error_id = f"err_{int(time.time() * 1000000)}"

        # Log the full exception with traceback
        logger.error(
            f"Unexpected error in {request.method} {request.url.path}: {str(exc)}",
            extra={
                "request_id": getattr(request.state, "request_id", "unknown"),
                "error_id": error_id,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "event_type": "unexpected_error"
            },
            exc_info=True
        )

        # Return user-friendly error response
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "type": "internal_server_error",
                    "message": "An unexpected error occurred. Please try again later.",
                    "error_id": error_id,
                    "status_code": 500,
                }
            },
        )
