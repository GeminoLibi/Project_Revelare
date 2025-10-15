"""
Evidence Models
Database models for evidence file management and processing.
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, JSON, LargeBinary
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from .base import Base, TimestampMixin


class EvidenceStatus(str, enum.Enum):
    """Evidence file processing status."""
    UPLOADED = "uploaded"
    SCANNING = "scanning"
    PROCESSED = "processed"
    FAILED = "failed"
    QUARANTINED = "quarantined"


class FileType(str, enum.Enum):
    """File type classifications."""
    DOCUMENT = "document"
    ARCHIVE = "archive"
    EMAIL = "email"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DATABASE = "database"
    LOG = "log"
    EXECUTABLE = "executable"
    SCRIPT = "script"
    WEB = "web"
    OTHER = "other"


class EvidenceFile(Base, TimestampMixin):
    """Evidence file model for tracking uploaded files."""

    __tablename__ = "evidence_files"

    # File Information
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    file_path = Column(String(1000), nullable=False)  # Path in storage
    original_filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False)  # in bytes
    file_hash = Column(String(128), nullable=False)  # SHA-256 hash
    mime_type = Column(String(100), nullable=True)

    # Classification
    file_type = Column(Enum(FileType), nullable=True)
    file_category = Column(String(100), nullable=True)  # From config

    # Processing Status
    status = Column(Enum(EvidenceStatus), default=EvidenceStatus.UPLOADED, nullable=False)
    processing_message = Column(Text, nullable=True)
    processed_at = Column(DateTime(timezone=True), nullable=True)

    # Security Scanning
    virus_scan_result = Column(String(50), nullable=True)
    virus_scan_details = Column(JSON, nullable=True)
    is_malicious = Column(Boolean, default=False, nullable=False)

    # Metadata
    file_metadata = Column(JSON, nullable=True)  # EXIF, etc.
    extracted_text = Column(Text, nullable=True)  # For search indexing

    # Storage Information
    storage_provider = Column(String(50), default="local", nullable=False)
    storage_bucket = Column(String(255), nullable=True)
    storage_key = Column(String(1000), nullable=True)

    # Audit Fields
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    case = relationship("Case", back_populates="evidence_files")
    uploaded_by_user = relationship("User")
    findings = relationship("Finding", back_populates="evidence_file")

    def __repr__(self) -> str:
        return f"<EvidenceFile(id={self.id}, filename='{self.original_filename}', status='{self.status}')>"

    def is_processed(self) -> bool:
        """Check if file has been processed."""
        return self.status == EvidenceStatus.PROCESSED

    def mark_as_processing(self, message: str = None) -> None:
        """Mark file as being processed."""
        self.status = EvidenceStatus.SCANNING
        if message:
            self.processing_message = message

    def mark_as_processed(self, message: str = None) -> None:
        """Mark file as successfully processed."""
        self.status = EvidenceStatus.PROCESSED
        self.processed_at = func.now()
        if message:
            self.processing_message = message

    def mark_as_failed(self, message: str) -> None:
        """Mark file as failed processing."""
        self.status = EvidenceStatus.FAILED
        self.processing_message = message

    def mark_as_quarantined(self, reason: str, details: dict = None) -> None:
        """Mark file as quarantined due to security issues."""
        self.status = EvidenceStatus.QUARANTINED
        self.is_malicious = True
        self.virus_scan_result = reason
        if details:
            self.virus_scan_details = details

    def get_display_size(self) -> str:
        """Get human-readable file size."""
        size_bytes = self.file_size
        if size_bytes is None or size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024.0 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        return f"{size_bytes".2f"} {size_names[i]}" if i > 0 else f"{int(size_bytes)} {size_names[i]}"


class Finding(Base, TimestampMixin):
    """Finding model for storing analysis results."""

    __tablename__ = "findings"

    # Core Information
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_file_id = Column(Integer, ForeignKey("evidence_files.id"), nullable=False)

    # Finding Details
    category = Column(String(100), nullable=False)  # IPv4, Email, URL, etc.
    value = Column(Text, nullable=False)  # The actual finding value
    context = Column(Text, nullable=True)  # Context where finding was found
    confidence = Column(Integer, default=100, nullable=False)  # 0-100

    # Classification
    severity = Column(String(20), nullable=True)  # low, medium, high, critical
    tags = Column(JSON, nullable=True)  # Additional classification tags

    # Enrichment Data
    enriched_data = Column(JSON, nullable=True)  # IP geolocation, etc.
    external_refs = Column(JSON, nullable=True)  # References to external databases

    # Processing Information
    processor = Column(String(100), nullable=True)  # Which processor found this
    processing_metadata = Column(JSON, nullable=True)  # Processing details

    # Relationships
    case = relationship("Case", back_populates="findings")
    evidence_file = relationship("EvidenceFile", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, category='{self.category}', value='{self.value[:50]}...')>"

    def is_high_confidence(self) -> bool:
        """Check if finding has high confidence."""
        return self.confidence >= 80

    def get_severity_level(self) -> str:
        """Get severity as string."""
        if self.severity:
            return self.severity
        # Auto-classify based on category and value
        return self._auto_classify_severity()

    def _auto_classify_severity(self) -> str:
        """Auto-classify severity based on finding characteristics."""
        # This would contain logic to automatically classify findings
        # For now, return medium as default
        return "medium"


class ProcessingJob(Base, TimestampMixin):
    """Processing job model for tracking background tasks."""

    __tablename__ = "processing_jobs"

    # Job Information
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    job_type = Column(String(100), nullable=False)  # extraction, analysis, report_generation
    job_status = Column(String(50), default="pending", nullable=False)

    # Progress Tracking
    progress = Column(Integer, default=0, nullable=False)  # 0-100
    current_step = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)

    # Timing
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    estimated_completion = Column(DateTime(timezone=True), nullable=True)

    # Error Handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)

    # Configuration
    job_config = Column(JSON, nullable=True)  # Job-specific configuration
    priority = Column(Integer, default=1, nullable=False)  # 1=low, 5=high

    # Relationships
    case = relationship("Case")

    def __repr__(self) -> str:
        return f"<ProcessingJob(id={self.id}, type='{self.job_type}', status='{self.job_status}')>"

    def mark_as_started(self) -> None:
        """Mark job as started."""
        self.job_status = "running"
        self.started_at = func.now()
        self.progress = 0

    def mark_as_completed(self, message: str = None) -> None:
        """Mark job as completed."""
        self.job_status = "completed"
        self.completed_at = func.now()
        self.progress = 100
        if message:
            self.message = message

    def mark_as_failed(self, error: str) -> None:
        """Mark job as failed."""
        self.job_status = "failed"
        self.error_message = error
        self.completed_at = func.now()

    def can_retry(self) -> bool:
        """Check if job can be retried."""
        return self.retry_count < self.max_retries

    def increment_retry(self) -> None:
        """Increment retry count."""
        self.retry_count += 1
