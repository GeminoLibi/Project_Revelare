"""
User Models
Database models for user management and authentication.
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from .base import Base, TimestampMixin


class UserTier(str, enum.Enum):
    """User access tiers."""
    HOBBYIST = "hobbyist"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    ADMIN = "admin"


class AccountStatus(str, enum.Enum):
    """Account status values."""
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    DEACTIVATED = "deactivated"


class AdminLevel(str, enum.Enum):
    """Admin privilege levels."""
    NONE = "none"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class User(Base, TimestampMixin):
    """User model for authentication and profile management."""

    __tablename__ = "users"

    # Basic Information
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # Profile Information
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    agency = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)

    # Account Settings
    access_tier = Column(Enum(UserTier), default=UserTier.HOBBYIST, nullable=False)
    admin_level = Column(Enum(AdminLevel), default=AdminLevel.NONE, nullable=False)
    account_status = Column(Enum(AccountStatus), default=AccountStatus.PENDING_VERIFICATION, nullable=False)

    # Verification and Security
    email_verified = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(255), nullable=True)
    email_verification_expires = Column(DateTime(timezone=True), nullable=True)

    # Multi-Factor Authentication
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255), nullable=True)

    # Account Security
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    password_changed_at = Column(DateTime(timezone=True), nullable=True)

    # Audit Fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    created_cases = relationship("Case", back_populates="created_by_user", foreign_keys="Case.created_by")
    updated_cases = relationship("Case", back_populates="updated_by_user", foreign_keys="Case.updated_by")
    sessions = relationship("UserSession", back_populates="user")
    created_by_user = relationship("User", remote_side=[id], foreign_keys=[created_by])
    updated_by_user = relationship("User", remote_side=[id], foreign_keys=[updated_by])

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email='{self.email}', tier='{self.access_tier}')>"

    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.account_status == AccountStatus.ACTIVE and not self.is_locked()

    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if self.account_locked_until is None:
            return False
        return self.account_locked_until > func.now()

    def can_access_case(self, case: "Case") -> bool:
        """Check if user can access a specific case."""
        # Admins can access all cases
        if self.admin_level in [AdminLevel.ADMIN, AdminLevel.SUPER_ADMIN]:
            return True

        # Users can access cases they created
        return case.created_by == self.id

    def increment_failed_logins(self) -> None:
        """Increment failed login attempts."""
        self.failed_login_attempts += 1

        # Lock account after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5:
            self.account_locked_until = func.now() + func.interval('30 minutes')

    def reset_failed_logins(self) -> None:
        """Reset failed login attempts on successful login."""
        self.failed_login_attempts = 0
        self.account_locked_until = None

    def verify_email(self) -> None:
        """Mark email as verified."""
        self.email_verified = True
        self.account_status = AccountStatus.ACTIVE
        self.email_verification_token = None
        self.email_verification_expires = None

    def update_password(self, new_hash: str) -> None:
        """Update password hash."""
        self.password_hash = new_hash
        self.password_changed_at = func.now()


class UserSession(Base, TimestampMixin):
    """User session model for tracking active sessions."""

    __tablename__ = "user_sessions"

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<UserSession(id={self.id}, user_id={self.user_id}, active={self.is_active})>"

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return self.expires_at <= func.now()

    def deactivate(self) -> None:
        """Deactivate the session."""
        self.is_active = False
