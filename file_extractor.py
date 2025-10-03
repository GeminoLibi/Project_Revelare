#!/usr/bin/env python3
"""
File extraction and renaming utilities for Project Revelare.
"""

import os
import shutil
import zipfile
import tempfile
import stat
from typing import Dict, List, Tuple, Any
from pathlib import Path
from logger import get_logger, RevelareLogger
from security import SecurityValidator
import datetime
from datetime import timezone
import datetime as dt

revelare_logger = RevelareLogger
logger = revelare_logger.get_logger()


def extract_and_rename_files(source_dir: str, project_prefix: str, output_dir: str) -> Dict[str, str]:
    file_mapping: Dict[str, str] = {}
    
    if not os.path.isdir(source_dir):
        logger.error(f"Source directory does not exist: {source_dir}")
        return file_mapping
    
    try:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create output directory {output_dir}: {e}")
        return file_mapping

    files_to_move = [os.path.join(source_dir, f) for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
    
    logger.info(f"Found {len(files_to_move)} files to rename")
    
    for i, file_path in enumerate(files_to_move):
        original_basename = os.path.basename(file_path)
        
        try:
            # Generate sequential short name (A, B, C... AA, AB, AC...)
            index = i
            base_26_suffix = ""
            while True:
                base_26_suffix = chr(65 + (index % 26)) + base_26_suffix
                index = index // 26 - 1
                if index < 0:
                    break
            
            _, original_ext = os.path.splitext(original_basename)
            
            short_name = f"{project_prefix}_{base_26_suffix}{original_ext}"
            new_path = os.path.join(output_dir, short_name)
            
            if file_path != new_path:
                shutil.move(file_path, new_path)
                logger.info(f"File moved and renamed: {original_basename} -> {short_name}")
            
            file_mapping[original_basename] = short_name
            
        except Exception as e:
            logger.error(f"Failed to move/rename file {file_path}: {e}")
            continue
    
    logger.info(f"Successfully processed {len(file_mapping)} files to {output_dir}")
    
    # Optional: Clean up the now empty source directory
    cleanup_temp_files(source_dir)
    
    return file_mapping


def safe_extract_archive(archive_path: str, extract_to: str) -> Tuple[bool, str]:
    try:
        # Validate ZIP file
        is_valid, error_msg, dangerous_files = SecurityValidator.validate_zip_file(archive_path)
        if not is_valid:
            return False, f"Invalid ZIP file: {error_msg}"
        
        # Extract safely (Delegated to SecurityValidator's implementation)
        # NOTE: safe_extract_archive is redundant here, but included for completeness.
        success, extract_error = SecurityValidator.safe_extract_zip(archive_path, extract_to)
        if not success:
            return False, f"Extraction failed: {extract_error}"
        
        return True, ""
        
    except Exception as e:
        return False, f"Unexpected error: {e}"

def get_file_info(file_path: str) -> Dict[str, Any]:
    try:
        file_path_obj = Path(file_path)
        stat_result = file_path_obj.stat()
        
        # NOTE: Assuming SecurityValidator.calculate_file_hash is defined/accessible
        file_hash = SecurityValidator.calculate_file_hash(file_path, hash_algo='sha256')

        return {
            "size_bytes": stat_result.st_size,
            "created_time_utc": dt.datetime.fromtimestamp(stat_result.st_ctime, tz=timezone.utc).isoformat(), 
            "modified_time_utc": dt.datetime.fromtimestamp(stat_result.st_mtime, tz=timezone.utc).isoformat(), 
            "access_time_utc": dt.datetime.fromtimestamp(stat_result.st_atime, tz=timezone.utc).isoformat(), 
            "is_file": file_path_obj.is_file(),
            "is_symlink": file_path_obj.is_symlink(),
            "sha256_hash": file_hash if file_hash else "Error calculating hash",
        }
    except FileNotFoundError:
        logger.warning(f"File not found: {file_path}")
        return {"error": "File Not Found"}
    except Exception as e:
        logger.error(f"Error getting file info for {file_path}: {e}")
        return {"error": str(e)}


def cleanup_temp_files(temp_path: str) -> bool:
    temp_path_obj = Path(temp_path)
    if not temp_path_obj.exists():
        return True

    try:
        if temp_path_obj.is_dir():
            shutil.rmtree(temp_path)
        elif temp_path_obj.is_file() or temp_path_obj.is_symlink():
            temp_path_obj.unlink(missing_ok=True)
            
        logger.info(f"Cleaned up temporary path: {temp_path}")
        return True
    
    except PermissionError as pe:
        logger.warning(f"Permission error during cleanup of {temp_path}. Attempting chmod/retry.")
        try:
            # NOTE: Assuming os.stat is imported or available (it is available via os)
            os.chmod(temp_path, stat.S_IWRITE) # Give write permission
            if temp_path_obj.is_dir():
                shutil.rmtree(temp_path)
            else:
                temp_path_obj.unlink(missing_ok=True)
            return True
        except Exception as retry_e:
            logger.critical(f"Failed final cleanup of {temp_path} even after chmod: {retry_e}")
            return False
            
    except Exception as e:
        logger.error(f"Error cleaning up temp path {temp_path}: {e}")
        return False