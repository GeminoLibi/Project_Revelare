"""
Authentication Utilities
JWT token management, password hashing, and authentication helpers.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from ..config import config
from ..database.models import User, UserSession, AdminLevel, AccountStatus


class PasswordManager:
    """Password hashing and verification utilities."""

    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash_password(self, password: str) -> str:
        """Hash a password for storage."""
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return self.pwd_context.verify(plain_password, hashed_password)

    def generate_password_reset_token(self, user_id: int) -> str:
        """Generate a password reset token."""
        return secrets.token_urlsafe(32)


class JWTManager:
    """JWT token creation and validation."""

    def __init__(self):
        self.secret_key = config.settings.SECRET_KEY
        self.algorithm = config.settings.ALGORITHM

    def create_access_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )

        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def create_refresh_token(
        self,
        data: Dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create a JWT refresh token."""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                days=config.settings.REFRESH_TOKEN_EXPIRE_DAYS
            )

        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt

    def verify_token(self, token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])

            if payload.get("type") != token_type:
                return None

            return payload

        except JWTError:
            return None


class AuthenticationService:
    """Main authentication service."""

    def __init__(self):
        self.password_manager = PasswordManager()
        self.jwt_manager = JWTManager()

    def authenticate_user(self, db: Session, email: str, password: str) -> Optional[User]:
        """Authenticate a user with email and password."""
        user = db.query(User).filter(
            and_(
                User.email == email.lower(),
                User.account_status == AccountStatus.ACTIVE
            )
        ).first()

        if not user:
            return None

        if not self.password_manager.verify_password(password, user.password_hash):
            # Increment failed login attempts
            user.increment_failed_logins()
            db.commit()
            return None

        # Reset failed login attempts on successful login
        user.reset_failed_logins()
        user.last_login_at = datetime.utcnow()
        db.commit()

        return user

    def create_user(
        self,
        db: Session,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        agency: Optional[str] = None,
        phone: Optional[str] = None,
        access_tier: str = "hobbyist"
    ) -> User:
        """Create a new user account."""
        password_hash = self.password_manager.hash_password(password)

        # Generate verification token
        verification_token = secrets.token_urlsafe(32)
        verification_expires = datetime.utcnow() + timedelta(hours=24)

        user = User(
            email=email.lower(),
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
            agency=agency,
            phone=phone,
            access_tier=access_tier,
            email_verification_token=verification_token,
            email_verification_expires=verification_expires,
            mfa_enabled=True  # Default MFA enabled
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return user

    def verify_email(self, db: Session, token: str) -> Optional[User]:
        """Verify user email with token."""
        user = db.query(User).filter(
            and_(
                User.email_verification_token == token,
                User.email_verification_expires > datetime.utcnow(),
                User.email_verified == False
            )
        ).first()

        if user:
            user.verify_email()
            db.commit()

        return user

    def create_session(
        self,
        db: Session,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> UserSession:
        """Create a new user session."""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(days=7)

        session = UserSession(
            user_id=user.id,
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at
        )

        db.add(session)
        db.commit()
        db.refresh(session)

        return session

    def get_user_from_session(self, db: Session, session_id: str) -> Optional[User]:
        """Get user from session ID."""
        session = db.query(UserSession).filter(
            and_(
                UserSession.session_id == session_id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            )
        ).first()

        if session:
            return session.user
        return None

    def revoke_session(self, db: Session, session_id: str) -> bool:
        """Revoke a user session."""
        session = db.query(UserSession).filter(
            UserSession.session_id == session_id
        ).first()

        if session:
            session.deactivate()
            db.commit()
            return True

        return False

    def revoke_all_user_sessions(self, db: Session, user_id: int) -> int:
        """Revoke all sessions for a user."""
        sessions = db.query(UserSession).filter(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )
        ).all()

        count = 0
        for session in sessions:
            session.deactivate()
            count += 1

        if count > 0:
            db.commit()

        return count

    def check_permissions(self, user: User, required_tier: str = None, required_admin_level: AdminLevel = None) -> bool:
        """Check if user has required permissions."""
        # Check account status
        if user.account_status != AccountStatus.ACTIVE:
            return False

        # Check access tier
        if required_tier:
            tier_hierarchy = {
                "hobbyist": 1,
                "professional": 2,
                "enterprise": 3,
                "admin": 4
            }

            user_tier_level = tier_hierarchy.get(user.access_tier.value, 0)
            required_tier_level = tier_hierarchy.get(required_tier, 0)

            if user_tier_level < required_tier_level:
                return False

        # Check admin level
        if required_admin_level:
            admin_hierarchy = {
                AdminLevel.NONE: 0,
                AdminLevel.MODERATOR: 1,
                AdminLevel.ADMIN: 2,
                AdminLevel.SUPER_ADMIN: 3
            }

            user_admin_level = admin_hierarchy.get(user.admin_level, 0)
            required_admin_level_value = admin_hierarchy.get(required_admin_level, 0)

            if user_admin_level < required_admin_level_value:
                return False

        return True


# Global instances
password_manager = PasswordManager()
jwt_manager = JWTManager()
auth_service = AuthenticationService()
