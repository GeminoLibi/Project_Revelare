"""Central database helpers for Project Revelare master indicator store."""
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List

from revelare.config.config import Config
from revelare.utils.logger import get_logger

logger = get_logger(__name__)


def get_db_connection(retries: int = 5, delay: float = 0.5) -> sqlite3.Connection:
    last_error = None
    for attempt in range(retries):
        try:
            conn = sqlite3.connect(Config.DATABASE, timeout=60)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=60000")
            return conn
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" in str(exc).lower() and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                continue
            raise
    raise last_error  # type: ignore[misc]


def list_db_cases() -> List[str]:
    if not Config.DATABASE or not __import__("os").path.exists(Config.DATABASE):
        return []
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT project_name FROM projects ORDER BY project_name")
        names = [row[0] for row in cursor.fetchall()]
        conn.close()
        return names
    except Exception as exc:
        logger.warning("Could not list DB cases: %s", exc)
        return []


def init_database() -> bool:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_value TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                project_name TEXT NOT NULL,
                context TEXT,
                timestamp_str TEXT,
                position INTEGER,
                confidence_score REAL,
                is_relevant INTEGER,
                source_port TEXT,
                destination_port TEXT,
                protocol TEXT,
                user_agent TEXT,
                session_id TEXT,
                source_path TEXT,
                source_hash TEXT,
                UNIQUE(indicator_value, project_name, context)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT UNIQUE NOT NULL,
                created_at DATETIME NOT NULL,
                status TEXT DEFAULT 'processing',
                total_files INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                completed_at DATETIME
            )
            """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators (indicator_value)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_project_name ON indicators (project_name)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators (indicator_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_project_type ON indicators (project_name, indicator_type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_project_type_value "
            "ON indicators (project_name, indicator_type, indicator_value)"
        )

        _ensure_indicator_source_columns(cursor)

        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
        return True

    except Exception as exc:
        logger.error("Failed to initialize database: %s", exc)
        return False


def _ensure_indicator_source_columns(cursor) -> None:
    cursor.execute("PRAGMA table_info(indicators)")
    cols = {row[1] for row in cursor.fetchall()}
    if "source_path" not in cols:
        cursor.execute("ALTER TABLE indicators ADD COLUMN source_path TEXT")
    if "source_hash" not in cols:
        cursor.execute("ALTER TABLE indicators ADD COLUMN source_hash TEXT")


def update_master_database(project_name: str, findings: Dict[str, Dict[str, Any]]) -> bool:
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        _ensure_indicator_source_columns(cursor)

        cursor.execute(
            """
            INSERT OR IGNORE INTO projects (project_name, created_at, status, total_findings)
            VALUES (?, ?, ?, ?)
            """,
            (project_name, datetime.now().isoformat(), "processing", 0),
        )

        total_inserted = 0

        from revelare.utils.data_enhancer import DataEnhancer
        from revelare.core.source_ingest import parse_source_fields

        temp_enhancer = DataEnhancer()

        for category, items in findings.items():
            if category == "Processing_Summary":
                continue

            for value, context in items.items():
                dummy_indicator = temp_enhancer.create_enhanced_indicator(
                    indicator=value,
                    category=category,
                    context=context,
                    file_name="DB_RECONSTRUCT",
                    position=0,
                )
                source_path, source_hash = parse_source_fields(context)

                try:
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO indicators
                        (indicator_value, indicator_type, project_name, context,
                         timestamp_str, position, confidence_score, is_relevant,
                         source_port, destination_port, protocol, user_agent, session_id,
                         source_path, source_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(value),
                            str(category),
                            str(project_name),
                            str(context),
                            str(dummy_indicator.timestamp),
                            int(dummy_indicator.position)
                            if dummy_indicator.position is not None
                            else 0,
                            float(dummy_indicator.confidence_score)
                            if dummy_indicator.confidence_score is not None
                            else 0.0,
                            int(dummy_indicator.is_relevant)
                            if dummy_indicator.is_relevant is not None
                            else 0,
                            str(dummy_indicator.source_port)
                            if dummy_indicator.source_port is not None
                            else None,
                            str(dummy_indicator.destination_port)
                            if dummy_indicator.destination_port is not None
                            else None,
                            str(dummy_indicator.protocol)
                            if dummy_indicator.protocol is not None
                            else None,
                            str(dummy_indicator.user_agent)
                            if dummy_indicator.user_agent is not None
                            else None,
                            str(dummy_indicator.session_id)
                            if dummy_indicator.session_id is not None
                            else None,
                            source_path or None,
                            source_hash or None,
                        ),
                    )

                    if cursor.rowcount > 0:
                        total_inserted += 1
                except Exception as exc:
                    logger.warning("Failed to insert indicator %s into DB: %s", value, exc)

        cursor.execute(
            """
            UPDATE projects SET status=?, total_findings=?, completed_at=? WHERE project_name=?
            """,
            ("completed", total_inserted, datetime.now().isoformat(), project_name),
        )

        conn.commit()
        conn.close()

        logger.info(
            "Database update complete. Inserted %s new indicators for %s.",
            total_inserted,
            project_name,
        )
        return True

    except Exception as exc:
        logger.error("Failed to update database: %s", exc)
        return False
