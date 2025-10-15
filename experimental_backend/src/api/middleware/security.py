"""
Security Middleware
Security headers, request validation, and protection middleware.
"""

import re
import logging
from typing import Optional

from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


logger = logging.getLogger(__name__)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security middleware for request validation and protection."""

    def __init__(self, app):
        super().__init__(app)
        self.sensitive_patterns = [
            re.compile(r'password', re.IGNORECASE),
            re.compile(r'secret', re.IGNORECASE),
            re.compile(r'token', re.IGNORECASE),
            re.compile(r'key', re.IGNORECASE),
        ]

    async def dispatch(self, request: Request, call_next):
        """Process request with security checks."""

        # Security headers
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy (configurable)
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp_policy

        return response
