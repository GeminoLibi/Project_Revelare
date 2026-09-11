"""
Temporary source ingest for Project Revelare.

Copies documents to a temp working directory for hash/extract/parse only.
Records the original source path (and source hash/timestamps) on findings
for audit. Does not keep a permanent duplicate of the document in the case vault.

Existing cases that already have copies under evidence/ or extracted_files/
are left in place. New ingest does not add to those directories.
"""
import hashlib
import json
import os
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from revelare.utils.logger import get_logger

logger = get_logger("source_ingest")

MANIFEST_FILENAME = "ingest_manifest.json"
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}
UPLOAD_SCHEME = "upload://"

_tls = threading.local()


def _registry() -> Dict[str, Dict[str, Any]]:
    if not hasattr(_tls, "by_path"):
        _tls.by_path = {}
    return _tls.by_path


def clear_source_registry() -> None:
    _registry().clear()


def _norm_path(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def register_staged_file(temp_path: str, meta: Dict[str, Any]) -> None:
    if not temp_path:
        return
    _registry()[_norm_path(temp_path)] = dict(meta)


def lookup_source_meta(file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not file_path:
        return None
    try:
        return _registry().get(_norm_path(file_path))
    except Exception:
        return None


def sha256_file(file_path: str, chunk_size: int = 1024 * 1024) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(file_path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except Exception as exc:
        logger.warning("Failed to hash %s: %s", file_path, exc)
        return None


def collect_source_metadata(
    readable_path: str,
    audit_path: Optional[str] = None,
    origin: str = "local_path",
    client_filename: Optional[str] = None,
) -> Dict[str, Any]:
    stat = os.stat(readable_path)
    source_path = audit_path if audit_path else os.path.abspath(readable_path)
    filename = client_filename or os.path.basename(source_path.replace("\\", "/").split("/")[-1])
    return {
        "source_path": source_path,
        "original_filename": filename,
        "source_hash": sha256_file(readable_path) or "",
        "source_size": int(stat.st_size),
        "source_mtime_utc": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        "source_ctime_utc": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
        "origin": origin,
        "ingested_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def inherit_member_metadata(parent_meta: Dict[str, Any], member_relpath: str) -> Dict[str, Any]:
    member_rel = member_relpath.replace("\\", "/")
    parent_path = parent_meta.get("source_path") or ""
    child = dict(parent_meta)
    child["source_path"] = "%s!%s" % (parent_path, member_rel)
    child["original_filename"] = os.path.basename(member_rel)
    child["archive_member"] = member_rel
    return child


def format_source_audit_fields(file_path: Optional[str] = None) -> List[str]:
    meta = lookup_source_meta(file_path)
    if not meta:
        return []
    parts = []
    if meta.get("source_path"):
        parts.append("SourcePath: %s" % meta["source_path"])
    if meta.get("source_hash"):
        parts.append("SourceHash: %s" % meta["source_hash"])
    if meta.get("source_mtime_utc"):
        parts.append("SourceMtime: %s" % meta["source_mtime_utc"])
    if meta.get("origin"):
        parts.append("SourceOrigin: %s" % meta["origin"])
    return parts


def parse_source_fields(context: Any) -> Tuple[str, str]:
    text = str(context or "")
    source_path = ""
    source_hash = ""
    for part in text.split(" | "):
        part = part.strip()
        if part.startswith("SourcePath:"):
            source_path = part.split(":", 1)[1].strip()
        elif part.startswith("SourceHash:"):
            source_hash = part.split(":", 1)[1].strip()
    return source_path, source_hash


def unique_dest_path(dest_dir: str, filename: str, index: int) -> str:
    dest_path = os.path.join(dest_dir, filename)
    if not os.path.exists(dest_path):
        return dest_path
    name, ext = os.path.splitext(filename)
    return os.path.join(dest_dir, "%s_%s%s" % (name, index, ext))


def _iter_source_files(source_path: str) -> List[str]:
    if os.path.isfile(source_path):
        return [source_path]
    if os.path.isdir(source_path):
        files = []
        for root, _dirs, names in os.walk(source_path):
            for name in names:
                files.append(os.path.join(root, name))
        return files
    return []


def stage_sources_to_temp(
    source_files: List[str],
    temp_dir: str,
    audit_sources: Optional[Dict[str, str]] = None,
    origin: str = "local_path",
) -> List[Dict[str, Any]]:
    """
    Copy source files into temp_dir for processing. Register audit metadata.
    Returns manifest records. Caller must delete temp_dir when finished.
    """
    audit_sources = audit_sources or {}
    records: List[Dict[str, Any]] = []
    Path(temp_dir).mkdir(parents=True, exist_ok=True)

    index = 0
    for source_path in source_files:
        if not source_path:
            continue
        audit_override = audit_sources.get(source_path)
        item_origin = origin
        if audit_override and str(audit_override).startswith(UPLOAD_SCHEME):
            item_origin = "web_upload"
        elif "extracted_files" in source_path.replace("\\", "/") or (
            os.path.sep + "evidence" + os.path.sep
        ) in os.path.abspath(source_path):
            if origin == "local_path":
                item_origin = "legacy_vault"

        for readable in _iter_source_files(source_path):
            index += 1
            try:
                filename = os.path.basename(readable)
                dest_path = unique_dest_path(temp_dir, filename, index)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy2(readable, dest_path)

                audit_path = audit_override or os.path.abspath(readable)
                client_name = filename
                if audit_override and str(audit_override).startswith(UPLOAD_SCHEME):
                    client_name = str(audit_override)[len(UPLOAD_SCHEME) :]

                meta = collect_source_metadata(
                    readable,
                    audit_path=audit_path,
                    origin=item_origin,
                    client_filename=client_name,
                )
                meta["temp_filename"] = os.path.basename(dest_path)
                register_staged_file(dest_path, meta)
                records.append(meta)

                ext = os.path.splitext(dest_path)[1].lower()
                if ext in ARCHIVE_EXTENSIONS:
                    _extract_and_register_archive(dest_path, temp_dir, meta)
            except Exception as exc:
                logger.error("Failed to stage %s: %s", readable, exc)
    return records


def _extract_and_register_archive(archive_temp_path: str, temp_dir: str, parent_meta: Dict[str, Any]) -> None:
    try:
        from revelare.utils.file_extractor import safe_extract_archive

        extract_root = os.path.join(
            temp_dir,
            "extracted_%s" % os.path.splitext(os.path.basename(archive_temp_path))[0],
        )
        os.makedirs(extract_root, exist_ok=True)
        success, error = safe_extract_archive(archive_temp_path, extract_root)
        if not success:
            logger.warning("Archive extract warning for %s: %s", archive_temp_path, error)

        for root, _dirs, names in os.walk(extract_root):
            for name in names:
                member_path = os.path.join(root, name)
                rel = os.path.relpath(member_path, extract_root)
                member_meta = inherit_member_metadata(parent_meta, rel)
                register_staged_file(member_path, member_meta)
    except Exception as exc:
        logger.warning("Failed to extract staged archive %s: %s", archive_temp_path, exc)


def write_ingest_manifest(case_dir: str, records: List[Dict[str, Any]]) -> str:
    Path(case_dir).mkdir(parents=True, exist_ok=True)
    manifest_path = os.path.join(case_dir, MANIFEST_FILENAME)
    existing: Dict[str, Any] = {"version": 1, "permanent_copies": False, "files": []}
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
                if isinstance(loaded, dict):
                    existing = loaded
                    existing.setdefault("files", [])
        except Exception as exc:
            logger.warning("Could not read existing ingest manifest: %s", exc)

    by_path = {}
    for rec in existing.get("files", []):
        key = rec.get("source_path") or rec.get("source_hash")
        if key:
            by_path[key] = rec
    for rec in records:
        stored = {k: v for k, v in rec.items() if k != "temp_filename"}
        key = stored.get("source_path") or stored.get("source_hash")
        if key:
            by_path[key] = stored
        else:
            existing["files"].append(stored)

    existing["version"] = 1
    existing["permanent_copies"] = False
    existing["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
    existing["files"] = list(by_path.values())
    existing["note"] = (
        "New ingest stores source path/hash only. Temporary processing copies are deleted. "
        "Older cases may still contain files under evidence/ or extracted_files/; "
        "those copies are not mass-deleted."
    )

    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(existing, handle, indent=2, ensure_ascii=False)
    return manifest_path


def load_ingest_manifest(case_dir: str) -> Dict[str, Any]:
    manifest_path = os.path.join(case_dir, MANIFEST_FILENAME)
    if not os.path.exists(manifest_path):
        return {"files": []}
    try:
        with open(manifest_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, dict):
                data.setdefault("files", [])
                return data
    except Exception as exc:
        logger.warning("Failed to load ingest manifest for %s: %s", case_dir, exc)
    return {"files": []}


def source_paths_from_manifest(case_dir: str) -> List[str]:
    paths = []
    for rec in load_ingest_manifest(case_dir).get("files", []):
        source_path = rec.get("source_path") or ""
        if not source_path or source_path.startswith(UPLOAD_SCHEME):
            continue
        if "!" in source_path:
            source_path = source_path.split("!", 1)[0]
        if os.path.isfile(source_path):
            paths.append(source_path)
    return paths
