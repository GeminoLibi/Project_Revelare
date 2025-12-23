import os
import shutil
import zipfile
import tempfile
import stat
import re
import hashlib
import subprocess
from typing import Dict, List, Tuple, Any
from pathlib import Path
from datetime import timezone
import datetime as dt

from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator
from revelare.config.config import Config

logger = RevelareLogger.get_logger(__name__)

def get_script_temp_dir() -> str:
    """
    Get the temp directory path in the script directory.
    Creates a 'temp' subdirectory in the project root if it doesn't exist.
    """
    # Get the project root (where revelare package is located)
    script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    temp_dir = os.path.join(script_dir, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

def mkdtemp_in_script_dir(prefix: str = 'revelare_', suffix: str = '') -> str:
    """
    Create a temporary directory in the script directory instead of system temp.
    """
    temp_base = get_script_temp_dir()
    return tempfile.mkdtemp(prefix=prefix, suffix=suffix, dir=temp_base)

def TemporaryDirectory_in_script_dir(prefix: str = 'revelare_', suffix: str = ''):
    """
    Create a TemporaryDirectory context manager in the script directory.
    Returns a context manager similar to tempfile.TemporaryDirectory.
    """
    temp_base = get_script_temp_dir()
    return tempfile.TemporaryDirectory(prefix=prefix, suffix=suffix, dir=temp_base)

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

def extract_archive_single(archive_path: str, extract_to: str) -> bool:
    """
    Extract a single archive file (zip, 7z, rar, etc.) to the target directory.
    This does NOT handle recursion, just extracting the immediate contents.
    """
    ext = os.path.splitext(archive_path)[1].lower()
    
    # 1. Try zipfile for .zip
    if ext == '.zip':
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # Check for encrypted files
                for info in zip_ref.infolist():
                    if info.flag_bits & 0x1:
                        logger.warning(f"Skipping encrypted zip file (password protected): {archive_path}")
                        return False
                zip_ref.extractall(extract_to)
            return True
        except RuntimeError as e:
            if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                logger.warning(f"Skipping encrypted zip file (runtime error): {archive_path}")
                return False
            logger.debug(f"Zip extraction runtime error for {archive_path}: {e}")
            # Fallthrough to try 7z
        except zipfile.BadZipFile:
            logger.warning(f"File {archive_path} looks like zip but failed to open with zipfile. Trying external tools.")
        except Exception as e:
            logger.error(f"Zip extraction failed for {archive_path}: {e}")
            # Fallthrough to try 7z

    # 2. Try 7z (covers 7z, rar, zip, tar, gz, etc.)
    seven_zip_paths = [
        "7z",
        "7za",
        os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "7-Zip", "7z.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "7-Zip", "7z.exe"),
        os.path.expanduser("~\\AppData\\Local\\Programs\\7-Zip\\7z.exe")
    ]
    
    seven_zip_exe = None
    for path in seven_zip_paths:
        if shutil.which(path):
            seven_zip_exe = path
            break
        if os.path.exists(path) and os.path.isfile(path):
            seven_zip_exe = path
            break
            
    if seven_zip_exe:
        try:
            # x: extract with full paths
            # -y: assume yes on all queries
            # -o: output directory (must handle spaces)
            # -p: password (we don't have one, but just in case we provide blank or handle prompt)
            # -p-: Do not query password
            cmd = [seven_zip_exe, "x", "-y", "-p-", f"-o{extract_to}", archive_path]
            
            # Run command
            result = subprocess.run(cmd, capture_output=True, text=True, errors='ignore')
            
            if result.returncode == 0:
                return True
            else:
                output = result.stderr + result.stdout
                if "Wrong password" in output or "Enter password" in output or "Can not open encrypted archive" in output:
                     logger.warning(f"Skipping encrypted archive (7z): {archive_path}")
                     return False
                
                logger.debug(f"7z extraction returned code {result.returncode} for {archive_path}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"7z execution failed for {archive_path}: {e}")
            return False
            
    logger.warning(f"No suitable extractor found for {archive_path} (7z not found)")
    return False

def safe_extract_archive(archive_path: str, extract_to: str, depth: int = 0, processed_archives: set = None) -> Tuple[bool, str]:
    """
    Recursively extract archive files, handling nested archives.
    No depth limit - processes all nested archives as needed.
    
    Args:
        archive_path: Path to the archive file to extract
        extract_to: Directory to extract files to
        depth: Current recursion depth (for logging only)
        processed_archives: Set of already processed archive paths to prevent infinite loops
    
    Returns:
        Tuple of (success: bool, error_message: str)
    """
    if processed_archives is None:
        processed_archives = set()
    
    # Normalize path to prevent duplicate processing
    normalized_archive_path = os.path.normpath(archive_path)
    if normalized_archive_path in processed_archives:
        logger.debug(f"Skipping already processed archive: {archive_path}")
        return True, ""
    
    processed_archives.add(normalized_archive_path)
    
    try:
        # Validate file exists
        if not os.path.exists(archive_path):
            return False, f"Archive file not found: {archive_path}"

        # Perform extraction
        extraction_success = extract_archive_single(archive_path, extract_to)
        if not extraction_success:
            return False, f"Failed to extract archive: {archive_path}"
        
        # Now look for nested archives in the extracted content
        extracted_archives = []
        
        # Walk the extraction directory to find all archives (including in subdirectories)
        for root, dirs, files in os.walk(extract_to):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                # Normalize path for comparison
                normalized_path = os.path.normpath(file_path)
                
                # Skip the original archive file itself if it happens to be in the target dir (unlikely but possible)
                if normalized_path == normalized_archive_path:
                    continue
                
                if os.path.isfile(file_path):
                    file_ext = os.path.splitext(file_path)[1].lower()
                    if file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                        # Only add if we haven't processed it yet
                        if normalized_path not in processed_archives:
                            extracted_archives.append(file_path)
        
        # Recursively extract nested archives
        for nested_archive in extracted_archives:
            logger.info(f"Extracting nested archive: {os.path.basename(nested_archive)}")
            # We extract nested archives IN PLACE (or we could create subdirs)
            # Standard behavior: extract to the same folder or a subfolder named after the archive?
            # 'extract_to' is the root extraction dir. If we extract nested archives into the SAME root, it might be messy.
            # Usually, we want to extract them where they are.
            
            nested_extract_dir = os.path.join(os.path.dirname(nested_archive), f"extracted_{os.path.basename(nested_archive)}")
            os.makedirs(nested_extract_dir, exist_ok=True)
            
            success, error = safe_extract_archive(nested_archive, nested_extract_dir, depth + 1, processed_archives)
            if not success:
                logger.warning(f"Failed to extract nested archive {nested_archive}: {error}")
        
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
