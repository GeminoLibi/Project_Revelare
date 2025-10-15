"""
User Service
Business logic for user management, authentication, and authorization.
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import logging

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from ...database.models import User, UserSession, AdminLevel, AccountStatus, UserTier
from ...utils.auth import auth_service, password_manager, jwt_manager
from ...config import config


logger = logging.getLogger(__name__)


class UserService:
    """Service for user management operations."""

    def __init__(self, db: Session):
        self.db = db

    def create_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        agency: Optional[str] = None,
        phone: Optional[str] = None,
        access_tier: str = "hobbyist",
        created_by: Optional[int] = None
    ) -> User:
        """Create a new user account."""

        # Validate access tier
        if access_tier not in [tier.value for tier in UserTier]:
            raise ValueError(f"Invalid access tier: {access_tier}")

        # Check if user already exists
        existing_user = self.db.query(User).filter(User.email == email.lower()).first()
        if existing_user:
            raise ValueError(f"User with email {email} already exists")

        # Create user
        user = auth_service.create_user(
            db=self.db,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            agency=agency,
            phone=phone,
            access_tier=access_tier
        )

        # Set created_by if provided
        if created_by:
            user.created_by = created_by

        self.db.commit()
        logger.info(f"User created: {user.email} (ID: {user.id})")
        return user

    def authenticate_user(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user and return tokens."""

        user = auth_service.authenticate_user(self.db, email, password)

        if not user:
            logger.warning(f"Failed login attempt for: {email}")
            return None

        # Create session
        session = auth_service.create_session(
            db=self.db,
            user=user,
            ip_address=None,  # Will be set by middleware
            user_agent=None   # Will be set by middleware
        )

        # Generate tokens
        access_token = jwt_manager.create_access_token(
            data={"sub": user.email, "user_id": user.id, "tier": user.access_tier.value}
        )

        refresh_token = jwt_manager.create_refresh_token(
            data={"sub": user.email, "user_id": user.id}
        )

        logger.info(f"User authenticated: {user.email} (ID: {user.id})")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": config.settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "access_tier": user.access_tier.value,
                "is_admin": user.admin_level != AdminLevel.NONE,
                "email_verified": user.email_verified
            }
        }

    def verify_email(self, token: str) -> bool:
        """Verify user email with token."""

        user = auth_service.verify_email(self.db, token)

        if user:
            logger.info(f"Email verified for user: {user.email} (ID: {user.id})")
            return True

        logger.warning(f"Invalid email verification token: {token}")
        return False

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """Refresh access token using refresh token."""

        # Verify refresh token
        payload = jwt_manager.verify_token(refresh_token, "refresh")

        if not payload:
            return None

        user_email = payload.get("sub")
        if not user_email:
            return None

        # Get user
        user = self.db.query(User).filter(
            and_(
                User.email == user_email,
                User.account_status == AccountStatus.ACTIVE
            )
        ).first()

        if not user:
            return None

        # Generate new access token
        access_token = jwt_manager.create_access_token(
            data={"sub": user.email, "user_id": user.id, "tier": user.access_tier.value}
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": config.settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return self.db.query(User).filter(User.id == user_id).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        return self.db.query(User).filter(User.email == email.lower()).first()

    def update_user_profile(
        self,
        user_id: int,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        agency: Optional[str] = None,
        phone: Optional[str] = None,
        updated_by: Optional[int] = None
    ) -> User:
        """Update user profile information."""

        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        # Update fields if provided
        if first_name is not None:
            user.first_name = first_name
        if last_name is not None:
            user.last_name = last_name
        if agency is not None:
            user.agency = agency
        if phone is not None:
            user.phone = phone

        if updated_by:
            user.updated_by = updated_by

        user.updated_at = datetime.utcnow()
        self.db.commit()

        logger.info(f"User profile updated: {user.email} (ID: {user.id})")
        return user

    def change_user_tier(self, user_id: int, new_tier: str, changed_by: int) -> User:
        """Change user's access tier."""

        # Validate new tier
        if new_tier not in [tier.value for tier in UserTier]:
            raise ValueError(f"Invalid access tier: {new_tier}")

        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        old_tier = user.access_tier.value
        user.access_tier = UserTier(new_tier)
        user.updated_by = changed_by
        user.updated_at = datetime.utcnow()

        self.db.commit()

        logger.info(f"User tier changed: {user.email} from {old_tier} to {new_tier} (by user {changed_by})")
        return user

    def deactivate_user(self, user_id: int, deactivated_by: int) -> User:
        """Deactivate a user account."""

        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        user.account_status = AccountStatus.DEACTIVATED
        user.updated_by = deactivated_by
        user.updated_at = datetime.utcnow()

        # Revoke all sessions
        auth_service.revoke_all_user_sessions(self.db, user_id)

        self.db.commit()

        logger.info(f"User deactivated: {user.email} (ID: {user.id}) by user {deactivated_by}")
        return user

    def get_user_sessions(self, user_id: int) -> List[UserSession]:
        """Get all active sessions for a user."""

        return self.db.query(UserSession).filter(
            and_(
                UserSession.user_id == user_id,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            )
        ).all()

    def revoke_user_session(self, user_id: int, session_id: str) -> bool:
        """Revoke a specific user session."""

        success = auth_service.revoke_session(self.db, session_id)

        if success:
            logger.info(f"Session revoked for user {user_id}: {session_id}")

        return success

    def revoke_all_user_sessions(self, user_id: int) -> int:
        """Revoke all sessions for a user."""

        count = auth_service.revoke_all_user_sessions(self.db, user_id)

        if count > 0:
            logger.info(f"All sessions revoked for user {user_id} ({count} sessions)")

        return count

    def get_user_statistics(self, user_id: int) -> Dict[str, Any]:
        """Get user statistics and activity summary."""

        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} not found")

        # Get session count
        active_sessions = len(self.get_user_sessions(user_id))

        # Get case count (if we had case service)
        # cases_count = case_service.get_user_cases_count(user_id)

        # Get last activity
        last_activity = user.last_login_at

        return {
            "user_id": user_id,
            "email": user.email,
            "access_tier": user.access_tier.value,
            "account_status": user.account_status.value,
            "email_verified": user.email_verified,
            "active_sessions": active_sessions,
            "last_login": last_activity.isoformat() if last_activity else None,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat()
        }

    def list_users(
        self,
        page: int = 1,
        per_page: int = 50,
        access_tier: Optional[str] = None,
        account_status: Optional[str] = None,
        search: Optional[str] = None
    ) -> Dict[str, Any]:
        """List users with filtering and pagination."""

        # Base query
        query = self.db.query(User)

        # Apply filters
        if access_tier:
            query = query.filter(User.access_tier == UserTier(access_tier))

        if account_status:
            query = query.filter(User.account_status == AccountStatus(account_status))

        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                or_(
                    User.first_name.ilike(search_filter),
                    User.last_name.ilike(search_filter),
                    User.email.ilike(search_filter),
                    User.agency.ilike(search_filter)
                )
            )

        # Get total count
        total = query.count()

        # Apply pagination
        offset = (page - 1) * per_page
        users = query.offset(offset).limit(per_page).all()

        # Convert to response format
        user_list = []
        for user in users:
            user_list.append({
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "agency": user.agency,
                "access_tier": user.access_tier.value,
                "account_status": user.account_status.value,
                "email_verified": user.email_verified,
                "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                "created_at": user.created_at.isoformat()
            })

        return {
            "users": user_list,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page
        }
