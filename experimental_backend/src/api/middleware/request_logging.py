"""
Request Logging Middleware
Logging middleware for request/response tracking and audit trails.
"""

import time
import json
import logging
from typing import Dict, Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


logger = logging.getLogger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging requests and responses."""

    async def dispatch(self, request: Request, call_next):
        """Log request details and response."""

        start_time = time.time()

        # Extract request details
        request_data = {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "headers": dict(request.headers),
            "client_ip": self._get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
        }

        # Log incoming request
        logger.info(
            f"Incoming request: {request.method} {request.url.path}",
            extra={
                "request": request_data,
                "event_type": "request_start"
            }
        )

        try:
            response = await call_next(request)

            # Calculate processing time
            process_time = time.time() - start_time

            # Extract response details
            response_data = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "process_time": round(process_time, 4),
            }

            # Log response
            log_level = logging.INFO
            if response.status_code >= 400:
                log_level = logging.WARNING
            elif response.status_code >= 500:
                log_level = logging.ERROR

            logger.log(
                log_level,
                f"Request completed: {request.method} {request.url.path} -> {response.status_code}",
                extra={
                    "request": request_data,
                    "response": response_data,
                    "event_type": "request_complete"
                }
            )

            # Add processing time header
            response.headers["X-Process-Time"] = str(process_time)

            return response

        except Exception as exc:
            # Calculate processing time
            process_time = time.time() - start_time

            # Log exception
            logger.error(
                f"Request failed: {request.method} {request.url.path} -> {type(exc).__name__}: {exc}",
                extra={
                    "request": request_data,
                    "error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                    },
                    "process_time": round(process_time, 4),
                    "event_type": "request_error"
                },
                exc_info=True
            )

            # Re-raise the exception
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Get the real client IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP if multiple are present
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        # Fall back to client host
        if request.client:
            return request.client.host

        return "unknown"
