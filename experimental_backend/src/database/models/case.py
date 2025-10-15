"""
Case Models
Database models for case management and investigation tracking.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from .base import Base, TimestampMixin


class CaseStatus(str, enum.Enum):
    """Case status values."""
    DRAFT = "draft"
    ACTIVE = "active"
    PROCESSING = "processing"
    COMPLETED = "completed"
    ARCHIVED = "archived"
    CANCELLED = "cancelled"


class CasePriority(str, enum.Enum):
    """Case priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class ClassificationLevel(str, enum.Enum):
    """Security classification levels."""
    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class Case(Base, TimestampMixin):
    """Case model for investigation management."""

    __tablename__ = "cases"

    # Basic Information
    case_number = Column(String(100), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Status and Priority
    status = Column(Enum(CaseStatus), default=CaseStatus.DRAFT, nullable=False)
    priority = Column(Enum(CasePriority), default=CasePriority.NORMAL, nullable=False)

    # Classification and Security
    classification_level = Column(Enum(ClassificationLevel), default=ClassificationLevel.UNCLASSIFIED, nullable=False)

    # Timeline
    incident_date = Column(DateTime(timezone=True), nullable=True)
    start_date = Column(DateTime(timezone=True), nullable=True)
    end_date = Column(DateTime(timezone=True), nullable=True)

    # Processing Information
    processing_status = Column(String(50), default="pending", nullable=False)
    processing_progress = Column(Integer, default=0, nullable=False)  # 0-100
    processing_message = Column(Text, nullable=True)

    # Metadata
    tags = Column(JSON, nullable=True)  # List of tags
    custom_fields = Column(JSON, nullable=True)  # Custom metadata

    # File Information
    total_files = Column(Integer, default=0, nullable=False)
    total_size = Column(Integer, default=0, nullable=False)  # in bytes
    processed_files = Column(Integer, default=0, nullable=False)

    # Audit Fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    created_by_user = relationship("User", foreign_keys=[created_by])
    updated_by_user = relationship("User", foreign_keys=[updated_by])
    assigned_user = relationship("User", foreign_keys=[assigned_to])
    evidence_files = relationship("EvidenceFile", back_populates="case")
    findings = relationship("Finding", back_populates="case")
    notes = relationship("CaseNote", back_populates="case")

    def __repr__(self) -> str:
        return f"<Case(id={self.id}, case_number='{self.case_number}', status='{self.status}')>"

    def is_processing(self) -> bool:
        """Check if case is currently being processed."""
        return self.status == CaseStatus.PROCESSING

    def is_completed(self) -> bool:
        """Check if case processing is completed."""
        return self.status == CaseStatus.COMPLETED

    def can_be_accessed_by(self, user: "User") -> bool:
        """Check if user can access this case."""
        # Users can access cases they created
        if self.created_by == user.id:
            return True

        # Users can access cases assigned to them
        if self.assigned_to == user.id:
            return True

        # Admins can access all cases
        if user.admin_level in ["admin", "super_admin"]:
            return True

        return False

    def update_processing_status(self, status: str, progress: int = None, message: str = None) -> None:
        """Update processing status and progress."""
        self.processing_status = status
        if progress is not None:
            self.processing_progress = max(0, min(100, progress))
        if message is not None:
            self.processing_message = message

    def mark_as_completed(self) -> None:
        """Mark case as completed."""
        self.status = CaseStatus.COMPLETED
        self.processing_status = "completed"
        self.processing_progress = 100
        self.end_date = func.now()

    def mark_as_processing(self) -> None:
        """Mark case as processing."""
        self.status = CaseStatus.PROCESSING
        self.processing_status = "processing"
        self.processing_progress = 0
        if self.start_date is None:
            self.start_date = func.now()

    def add_evidence_file(self, file_path: str, file_size: int, file_hash: str) -> "EvidenceFile":
        """Add an evidence file to this case."""
        from .evidence import EvidenceFile

        evidence_file = EvidenceFile(
            case_id=self.id,
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash
        )

        self.evidence_files.append(evidence_file)
        self.total_files += 1
        self.total_size += file_size

        return evidence_file


class CaseNote(Base, TimestampMixin):
    """Case notes and comments."""

    __tablename__ = "case_notes"

    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False)
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False, nullable=False)  # Internal notes vs user-facing

    # Relationships
    case = relationship("Case", back_populates="notes")
    user = relationship("User")

    def __repr__(self) -> str:
        return f"<CaseNote(id={self.id}, case_id={self.case_id}, title='{self.title}')>"
