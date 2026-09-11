#!/usr/bin/env python3
"""
File Deduplication Utilities
Provides quick hash (size+mtime) and full hash (SHA256) for duplicate detection.
"""
import os
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from revelare.utils.logger import get_logger

logger = get_logger("file_deduplication")


def quick_hash(file_path: Path) -> str:
    """
    Generate a quick hash using file size and modification time.
    Fast but not cryptographically secure - used for initial filtering.
    
    Args:
        file_path: Path to file
        
    Returns:
        Hash string in format: "size_mtime"
    """
    try:
        stat = file_path.stat()
        return f"{stat.st_size}_{stat.st_mtime}"
    except Exception as e:
        logger.debug(f"Failed to get quick hash for {file_path}: {e}")
        return ""


def full_hash(file_path: Path, chunk_size: int = 8192) -> Optional[str]:
    """
    Generate SHA256 hash of file contents.
    Used for definitive duplicate detection.
    
    Args:
        file_path: Path to file
        chunk_size: Chunk size for reading large files
        
    Returns:
        SHA256 hash string or None if error
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logger.warning(f"Failed to compute full hash for {file_path}: {e}")
        return None


def check_duplicate_in_revelare(file_path: Path, revelare_cases_dir: Path, 
                                 quick_hash_cache: Optional[Dict[str, Set[str]]] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if a file already exists in Revelare cases directory.
    Uses quick hash first, then full hash for matches.
    
    Args:
        file_path: Path to file to check
        revelare_cases_dir: Path to Revelare cases directory
        quick_hash_cache: Optional pre-computed cache of quick hashes
        
    Returns:
        Tuple of (is_duplicate, duplicate_case_name, duplicate_file_path)
    """
    if not file_path.exists() or not file_path.is_file():
        return False, None, None

    manifest_hit = _check_manifest_duplicate(file_path, revelare_cases_dir)
    if manifest_hit[0]:
        return manifest_hit
    
    file_quick_hash = quick_hash(file_path)
    if not file_quick_hash:
        return False, None, None
    
    # Build quick hash cache if not provided
    if quick_hash_cache is None:
        quick_hash_cache = build_quick_hash_index(revelare_cases_dir)
    
    # Check if quick hash matches any existing file
    matching_files = quick_hash_cache.get(file_quick_hash, set())
    
    if not matching_files:
        return False, None, None
    
    # Quick hash matches - need to verify with full hash
    file_full_hash = full_hash(file_path)
    if not file_full_hash:
        return False, None, None
    
    # Check each matching file
    for existing_file_path in matching_files:
        existing_path = Path(existing_file_path)
        if not existing_path.exists():
            continue
        
        existing_full_hash = full_hash(existing_path)
        if existing_full_hash == file_full_hash:
            # Found duplicate - extract case name from path
            case_name = None
            try:
                # Path format: revelare_cases_dir/case_name/...
                parts = existing_path.parts
                cases_index = None
                for i, part in enumerate(parts):
                    if part == revelare_cases_dir.name or str(revelare_cases_dir) in str(existing_path):
                        if i + 1 < len(parts):
                            case_name = parts[i + 1]
                            break
                # Fallback: try to find case name by checking parent directories
                if case_name is None:
                    for parent in existing_path.parents:
                        if parent.parent == revelare_cases_dir:
                            case_name = parent.name
                            break
            except Exception as e:
                logger.debug(f"Failed to extract case name from {existing_path}: {e}")
            
            return True, case_name, str(existing_path)
    
    return False, None, None


def _check_manifest_duplicate(file_path: Path, revelare_cases_dir: Path) -> Tuple[bool, Optional[str], Optional[str]]:
    """Match against ingest_manifest.json source hashes (no vault copy required)."""
    file_full_hash = full_hash(file_path)
    if not file_full_hash or not revelare_cases_dir.exists():
        return False, None, None
    try:
        from revelare.core.source_ingest import load_ingest_manifest
    except Exception:
        return False, None, None
    for case_dir in revelare_cases_dir.iterdir():
        if not case_dir.is_dir() or case_dir.name.startswith('.'):
            continue
        for rec in load_ingest_manifest(str(case_dir)).get('files', []):
            if rec.get('source_hash') == file_full_hash:
                return True, case_dir.name, rec.get('source_path')
    return False, None, None


def build_quick_hash_index(revelare_cases_dir: Path, 
                          exclude_dirs: Optional[Set[str]] = None) -> Dict[str, Set[str]]:
    """
    Build an index of quick hashes for all files in Revelare cases.
    
    Args:
        revelare_cases_dir: Path to Revelare cases directory
        exclude_dirs: Set of directory names to exclude (e.g., {'temp', '__pycache__'})
        
    Returns:
        Dictionary mapping quick_hash -> set of file paths
    """
    if exclude_dirs is None:
        exclude_dirs = {'temp', '__pycache__', '.git', 'logs', 'reports', 'exports'}
    
    index = defaultdict(set)
    
    if not revelare_cases_dir.exists():
        logger.warning(f"Revelare cases directory not found: {revelare_cases_dir}")
        return index
    
    logger.info(f"Building quick hash index for {revelare_cases_dir}...")
    file_count = 0
    
    for case_dir in revelare_cases_dir.iterdir():
        if not case_dir.is_dir() or case_dir.name.startswith('.'):
            continue
        
        # Skip excluded directories
        if case_dir.name in exclude_dirs:
            continue
        
        # Scan all files in case directory
        for file_path in case_dir.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip files in excluded subdirectories
            if any(excluded in file_path.parts for excluded in exclude_dirs):
                continue
            
            try:
                qhash = quick_hash(file_path)
                if qhash:
                    index[qhash].add(str(file_path))
                    file_count += 1
            except Exception as e:
                logger.debug(f"Failed to index {file_path}: {e}")
                continue
    
    logger.info(f"Indexed {file_count} files with {len(index)} unique quick hashes")
    return index


def find_cross_case_duplicates(revelare_cases_dir: Path,
                               exclude_dirs: Optional[Set[str]] = None) -> Dict[str, List[Dict[str, str]]]:
    """
    Find duplicate files across different case directories.
    
    Args:
        revelare_cases_dir: Path to Revelare cases directory
        exclude_dirs: Set of directory names to exclude
        
    Returns:
        Dictionary mapping full_hash -> list of file info dicts
        Each dict contains: {'case': case_name, 'path': file_path, 'size': file_size}
    """
    if exclude_dirs is None:
        exclude_dirs = {'temp', '__pycache__', '.git', 'logs', 'reports', 'exports'}
    
    # First pass: build quick hash index
    quick_index = build_quick_hash_index(revelare_cases_dir, exclude_dirs)
    
    # Second pass: for files with matching quick hashes, compute full hashes
    full_hash_groups = defaultdict(list)
    
    logger.info("Computing full hashes for potential duplicates...")
    processed = 0
    
    for quick_hash_val, file_paths in quick_index.items():
        if len(file_paths) < 2:
            continue  # No potential duplicates
        
        # Compute full hash for each file
        for file_path_str in file_paths:
            file_path = Path(file_path_str)
            if not file_path.exists():
                continue
            
            full_hash_val = full_hash(file_path)
            if full_hash_val:
                # Extract case name
                case_name = None
                try:
                    for parent in file_path.parents:
                        if parent.parent == revelare_cases_dir:
                            case_name = parent.name
                            break
                except Exception:
                    pass
                
                if case_name:
                    full_hash_groups[full_hash_val].append({
                        'case': case_name,
                        'path': str(file_path),
                        'size': file_path.stat().st_size
                    })
                    processed += 1
                    if processed % 100 == 0:
                        logger.debug(f"Processed {processed} files...")
    
    # Filter to only actual duplicates (2+ files with same hash)
    duplicates = {h: files for h, files in full_hash_groups.items() if len(files) > 1}
    
    logger.info(f"Found {len(duplicates)} duplicate file groups across cases")
    return duplicates


def format_duplicate_report(duplicates: Dict[str, List[Dict[str, str]]]) -> str:
    """
    Format duplicate findings into a human-readable report.
    
    Args:
        duplicates: Dictionary from find_cross_case_duplicates
        
    Returns:
        Formatted report string
    """
    if not duplicates:
        return "No duplicate files found across cases.\n"
    
    report_lines = [
        f"Found {len(duplicates)} duplicate file groups across cases:\n",
        "=" * 80
    ]
    
    for i, (file_hash, files) in enumerate(duplicates.items(), 1):
        report_lines.append(f"\nDuplicate Group {i} (Hash: {file_hash[:16]}...):")
        report_lines.append(f"  File size: {files[0]['size']:,} bytes")
        report_lines.append(f"  Found in {len(files)} cases:")
        
        for file_info in files:
            report_lines.append(f"    - Case: {file_info['case']}")
            report_lines.append(f"      Path: {file_info['path']}")
        
        report_lines.append("")
    
    return "\n".join(report_lines)

