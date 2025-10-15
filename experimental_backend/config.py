"""
Project Revelare - Configuration Management
Comprehensive configuration system with environment variable support and validation.
"""

import os
import secrets
from typing import List, Dict, Any, Optional
from pathlib import Path
from pydantic import BaseSettings, validator, Field
import logging


class Settings(BaseSettings):
    """Application settings with validation and environment variable support."""

    # Security
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Project Revelare"
    PROJECT_DESCRIPTION: str = "Digital Forensics & Investigation Platform"
    VERSION: str = "2.0.0"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8080",
        "https://project-revelare.pages.dev"
    ]

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Database
    DATABASE_URL: str = "sqlite:///./revelare.db"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    DATABASE_POOL_TIMEOUT: int = 30

    # File Processing
    UPLOAD_DIR: str = "./uploads"
    MAX_FILE_SIZE: int = 2 * 1024 * 1024 * 1024  # 2GB
    ALLOWED_EXTENSIONS: Dict[str, List[str]] = {
        "documents": [".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".rtf"],
        "archives": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
        "emails": [".eml", ".msg", ".mbox"],
        "images": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
        "videos": [".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv"],
        "audio": [".mp3", ".wav", ".flac", ".aac", ".ogg"],
        "databases": [".db", ".sqlite", ".sqlite3"],
        "logs": [".log", ".csv", ".json", ".xml", ".yaml", ".yml"],
        "executables": [".exe", ".dll", ".so", ".dylib", ".app"],
        "scripts": [".py", ".js", ".sh", ".bat", ".ps1"],
        "web": [".html", ".htm", ".css", ".js", ".json", ".xml"],
        "other": [".md", ".rst", ".tex", ".odt"]
    }

    # Processing
    PROCESSING_TIMEOUT: int = 3600  # 1 hour
    MAX_CONCURRENT_PROCESSES: int = 4
    TEMP_DIR: str = "./temp"
    RESULTS_DIR: str = "./results"

    # Security Scanning
    VIRUS_SCAN_ENABLED: bool = True
    VIRUS_SCAN_TIMEOUT: int = 300  # 5 minutes
    MALWARE_HASHES_API: Optional[str] = None

    # External Services
    OPENAI_API_KEY: Optional[str] = None
    GOOGLE_API_KEY: Optional[str] = None
    IPSTACK_API_KEY: Optional[str] = None
    SENDGRID_API_KEY: Optional[str] = None
    TURNSTILE_SECRET_KEY: Optional[str] = None

    # Email Configuration
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE: Optional[str] = "./logs/revelare.log"
    LOG_MAX_SIZE: int = 100 * 1024 * 1024  # 100MB
    LOG_BACKUP_COUNT: int = 5

    # Monitoring
    SENTRY_DSN: Optional[str] = None
    PROMETHEUS_ENABLED: bool = True

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds

    # Caching
    REDIS_URL: Optional[str] = None
    CACHE_TTL: int = 300  # 5 minutes

    class Config:
        env_file = ".env"
        case_sensitive = True


class ConfigManager:
    """Configuration manager with validation and environment setup."""

    def __init__(self):
        self.settings = Settings()
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Validate all configuration settings."""
        errors = []

        # Check required directories
        required_dirs = [
            Path(self.settings.UPLOAD_DIR),
            Path(self.settings.TEMP_DIR),
            Path(self.settings.RESULTS_DIR),
        ]

        for directory in required_dirs:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                # Test write permissions
                test_file = directory / ".config_test"
                test_file.write_text("test")
                test_file.unlink()
            except Exception as e:
                errors.append(f"Cannot create or write to directory '{directory}': {e}")

        # Check database connectivity
        if self.settings.DATABASE_URL.startswith("sqlite"):
            db_path = Path(self.settings.DATABASE_URL.replace("sqlite:///", ""))
            try:
                db_path.parent.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create database directory: {e}")

        # Check external service keys
        if self.settings.VIRUS_SCAN_ENABLED and not self.settings.MALWARE_HASHES_API:
            errors.append("Virus scanning enabled but no malware API key provided")

        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors)
            raise ValueError(error_msg)

    def get_database_url(self) -> str:
        """Get database URL with proper async support."""
        if self.settings.DATABASE_URL.startswith("sqlite"):
            return self.settings.DATABASE_URL.replace("sqlite://", "sqlite+aiosqlite://")
        return self.settings.DATABASE_URL

    def get_cors_origins(self) -> List[str]:
        """Get CORS origins based on environment."""
        if self.settings.DEBUG:
            return ["*"]  # Allow all in development
        return self.settings.BACKEND_CORS_ORIGINS

    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.settings.DEBUG

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return not self.settings.DEBUG


# Global configuration instance
config = ConfigManager()


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with proper configuration."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, config.settings.LOG_LEVEL))

        # Create formatter
        formatter = logging.Formatter(config.settings.LOG_FORMAT)
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        logger.setLevel(getattr(logging, config.settings.LOG_LEVEL))

        # Prevent duplicate handlers
        logger.propagate = False

    return logger


# Configure root logger
logging.basicConfig(
    level=getattr(logging, config.settings.LOG_LEVEL),
    format=config.settings.LOG_FORMAT
)
