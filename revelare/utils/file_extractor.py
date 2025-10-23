import os
import shutil
import zipfile
import tempfile
import stat
import re
import hashlib
from typing import Dict, List, Tuple, Any
from pathlib import Path
from datetime import timezone
import datetime as dt

from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator

logger = RevelareLogger.get_logger(__name__)

def normalize_long_path(file_path: str, max_length: int = 200) -> str:
    """
    Normalize file paths that are too long for Windows by creating shorter names.
    Preserves file extension and creates a hash-based short name.
    """
    if len(file_path) <= max_length:
        return file_path
    
    # Get directory and filename
    dir_path = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    
    # Get file extension
    name, ext = os.path.splitext(filename)
    
    # Create a hash of the original path for uniqueness
    path_hash = hashlib.md5(file_path.encode('utf-8')).hexdigest()[:8]
    
    # Create a shortened name
    # Keep first 20 chars of original name, add hash, add extension
    short_name = f"{name[:20]}_{path_hash}{ext}"
    
    # Ensure the new path is within limits
    new_path = os.path.join(dir_path, short_name)
    
    # If still too long, use just hash + extension
    if len(new_path) > max_length:
        short_name = f"{path_hash}{ext}"
        new_path = os.path.join(dir_path, short_name)
    
    return new_path

def normalize_file_path(file_path: str, case_name: str = None) -> Tuple[str, str]:
    """
    Normalize a file path to handle Windows path length limits and special characters.
    Returns (normalized_path, original_path) tuple.
    """
    original_path = file_path
    
    # Check if path is too long
    if len(file_path) > 250:  # Leave some buffer for Windows 260 char limit
        logger.warning(f"Path too long, normalizing: {file_path[:100]}...")
        
        # Try to normalize the path
        normalized_path = normalize_long_path(file_path)
        
        # If normalization would create a conflict, add timestamp
        if os.path.exists(normalized_path) and normalized_path != file_path:
            name, ext = os.path.splitext(normalized_path)
            timestamp = str(int(dt.datetime.now().timestamp()))[-6:]  # Last 6 digits
            normalized_path = f"{name}_{timestamp}{ext}"
        
        return normalized_path, original_path
    
    return file_path, original_path

def extract_and_rename_files(source_dir: str, project_prefix: str, output_dir: str) -> Dict[str, str]:
    file_mapping = {}
    if not os.path.isdir(source_dir):
        logger.error(f"Source directory does not exist: {source_dir}")
        return file_mapping
    
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create output directory {output_dir}: {e}")
        return file_mapping

    files_to_move = [os.path.join(dp, f) for dp, dn, filenames in os.walk(source_dir) for f in filenames]
    
    logger.info(f"Found {len(files_to_move)} files to process in {source_dir}")
    
    for i, file_path in enumerate(files_to_move):
        try:
            relative_path = os.path.relpath(file_path, source_dir)
            original_basename = os.path.basename(relative_path)
            
            index = i
            base_26_suffix = ""
            while True:
                base_26_suffix = chr(65 + (index % 26)) + base_26_suffix
                index //= 26
                if index == 0:
                    break
                index -= 1
            
            _, original_ext = os.path.splitext(original_basename)
            short_name = f"{project_prefix}_{base_26_suffix}{original_ext}"
            new_path = os.path.join(output_dir, short_name)
            
            if file_path != new_path:
                shutil.move(file_path, new_path)
            
            file_mapping[relative_path] = short_name
            
        except Exception as e:
            logger.error(f"Failed to move/rename file {file_path}: {e}")
            continue
    
    logger.info(f"Successfully processed {len(file_mapping)} files to {output_dir}")
    cleanup_temp_files(source_dir)
    return file_mapping

def safe_extract_archive(archive_path: str, extract_to: str) -> Tuple[bool, str]:
    try:
        is_valid, error_msg, _ = SecurityValidator.validate_zip_file(archive_path)
        if not is_valid:
            return False, f"Invalid archive: {error_msg}"
        
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            for member in zip_ref.infolist():
                target_path = os.path.join(extract_to, member.filename)
                if not SecurityValidator.is_safe_path(target_path, extract_to):
                    logger.warning(f"Skipping unsafe path in archive: {member.filename}")
                    continue
                zip_ref.extract(member, extract_to)
        return True, ""
        
    except Exception as e:
        return False, f"Unexpected error during extraction: {e}"

def get_file_info(file_path: str) -> Dict[str, Any]:
    try:
        file_path_obj = Path(file_path)
        stat_result = file_path_obj.stat()
        
        return {
            "size_bytes": stat_result.st_size,
            "created_time_utc": dt.datetime.fromtimestamp(stat_result.st_ctime, tz=timezone.utc).isoformat(), 
            "modified_time_utc": dt.datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat(), 
            "access_time_utc": dt.datetime.fromtimestamp(stat_result.st_atime, tz=timezone.utc).isoformat(), 
        }
    except Exception as e:
        logger.error(f"Error getting file info for {file_path}: {e}")
        return {"error": str(e)}

def cleanup_temp_files(temp_path: str) -> bool:
    if not temp_path or not os.path.exists(temp_path):
        return True
    try:
        shutil.rmtree(temp_path)
        logger.info(f"Cleaned up temporary path: {temp_path}")
        return True
    except Exception as e:
        logger.error(f"Error cleaning up temp path {temp_path}: {e}")
        return False