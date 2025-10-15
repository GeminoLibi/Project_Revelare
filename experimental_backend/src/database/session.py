"""
Database Session Management
SQLAlchemy session management with connection pooling and async support.
"""

from typing import Generator
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool

from ..config import config


logger = logging.getLogger(__name__)


class DatabaseManager:
    """Database connection and session management."""

    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Initialize database engine and session factory."""
        try:
            # Create engine with proper configuration
            self.engine = create_engine(
                config.get_database_url(),
                poolclass=QueuePool,
                pool_size=config.settings.DATABASE_POOL_SIZE,
                max_overflow=config.settings.DATABASE_MAX_OVERFLOW,
                pool_timeout=config.settings.DATABASE_POOL_TIMEOUT,
                pool_pre_ping=True,  # Verify connections before use
                echo=config.settings.DEBUG,  # SQL logging in debug mode
                future=True,  # Use SQLAlchemy 2.0 style
            )

            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )

            logger.info(f"Database engine initialized with URL: {config.get_database_url()}")

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def get_engine(self):
        """Get the SQLAlchemy engine."""
        return self.engine

    def create_tables(self) -> None:
        """Create all database tables."""
        from ..database.models import Base

        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise

    def drop_tables(self) -> None:
        """Drop all database tables (development only)."""
        from ..database.models import Base

        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.warning("Database tables dropped")
        except Exception as e:
            logger.error(f"Failed to drop database tables: {e}")
            raise


# Global database manager instance
db_manager = DatabaseManager()


def get_db() -> Generator[Session, None, None]:
    """Dependency for getting database sessions."""
    db = db_manager.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_db_sync() -> Session:
    """Get a synchronous database session."""
    return db_manager.SessionLocal()


# Initialize database tables on import
try:
    db_manager.create_tables()
except Exception as e:
    logger.warning(f"Could not create database tables on startup: {e}")
    # This might happen if tables already exist or during testing
