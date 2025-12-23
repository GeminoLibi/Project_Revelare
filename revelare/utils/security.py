import os
import re
import hashlib
import zipfile
import ipaddress
import logging
from typing import List, Tuple, Optional, Any
from pathlib import Path

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger

logger = get_logger(__name__) 
security_logger = RevelareLogger.get_logger('security') 

class SecurityValidator:
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        if not filename: return "unnamed_file"
        
        filename = os.path.basename(filename)
        filename = re.sub(r'[<>:"/\\|?*\x00]', '_', filename)
        
        max_len = getattr(Config, 'MAX_FILENAME_LENGTH', 255) 
        
        if len(filename) > max_len:
            name, ext = os.path.splitext(filename)
            filename = name[:max_len - len(ext) - 1] + ext
        
        if not filename or filename in ('.', '..'): return "sanitized_file"
        return filename
    
    @staticmethod
    def validate_project_name(project_name: str) -> Tuple[bool, str]:
        if not project_name:
            return False, "Project name cannot be empty"
        
        max_len = getattr(Config, 'MAX_PROJECT_NAME_LENGTH', 100)
        if len(project_name) > max_len:
            return False, f"Project name too long (max {max_len} characters)"
        
        if re.search(r'[<>:"/\\|?*]', project_name):
            security_logger.warning(f"Project name contains invalid characters: {project_name}")
            return False, "Project name contains invalid characters"
        
        if '..' in project_name or project_name.startswith('/'):
            security_logger.critical(f"Path traversal attempt in project name: {project_name}")
            return False, "Project name contains traversal attempts"
        
        return True, "Valid"
        
    @staticmethod
    def is_safe_path(target_path: str, base_path: Optional[str] = None) -> bool:
        try:
            if not isinstance(target_path, str) or not target_path.strip():
                security_logger.warning("Empty or invalid path provided to is_safe_path")
                return False

            if '\x00' in target_path:
                 security_logger.critical("Null byte injection attempt blocked.")
                 return False

            try:
                target_abs_path = Path(os.path.abspath(target_path)).resolve()
            except (OSError, ValueError) as e:
                security_logger.error(f"Failed to resolve path '{target_path}': {e}")
                return False

            if base_path:
                try:
                    base_abs_path = Path(os.path.abspath(base_path)).resolve()
                except (OSError, ValueError) as e:
                    security_logger.error(f"Failed to resolve base path '{base_path}': {e}")
                    return False
                
                if not str(target_abs_path).startswith(str(base_abs_path)):
                     security_logger.critical(f"Directory Traversal blocked: {target_abs_path} is outside {base_abs_path}")
                     return False

            max_path_len = getattr(Config, 'MAX_FILE_PATH_LENGTH', 4096)
            if len(str(target_abs_path)) > max_path_len:
                 security_logger.warning(f"Path length exceeds limit: {target_path}")
                 return False

            return True

        except Exception as e:
            security_logger.error(f"Unexpected error in is_safe_path for '{target_path}': {e}")
            return False
            
    @staticmethod
    def validate_zip_file(zip_path: str) -> Tuple[bool, str, List[str]]:
        """
        Validate ZIP file for path traversal attacks only.
        No file count or size limits - process all nested archives as needed.
        """
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                file_infos = zip_file.infolist()

                # Only check for path traversal attacks - no zip bomb protection
                for member in file_infos:
                    target_path = os.path.join("temp_dir", member.filename)
                    if not SecurityValidator.is_safe_path(target_path, "temp_dir"):
                        security_logger.critical(f"ZIP contains dangerous path (traversal attempt): {member.filename}")
                        return False, "Zip contains dangerous paths", [member.filename]
                
                return True, "Valid", []
        
        except zipfile.BadZipFile:
            return False, "Invalid ZIP file format", []
        except Exception as e:
            return False, f"Error validating ZIP: {e}", []

class InputValidator:
    
    @staticmethod
    def validate_indicator_search(search_term: str) -> Tuple[bool, str]:
        max_len = getattr(Config, 'MAX_SEARCH_TERM_LENGTH', 1000)
        if not search_term or len(search_term) > max_len:
            return False, "Search term is empty or too long"
        
        dangerous_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|WAITFOR)\b)',
            r'(--|;|\/\*|\*\/)'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, search_term, re.IGNORECASE):
                security_logger.critical(f"Potential SQLi attempt blocked in search term: {search_term}")
                return False, "Search term contains potentially malicious patterns"
        
        return True, "Valid"
    
    @staticmethod
    def sanitize_html_input(text: str) -> str:
        if not text: return ""
        
        text = str(text)
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        
        max_len = getattr(Config, 'MAX_HTML_INPUT_LENGTH', 10000)
        return text[:max_len]
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        if not ip: return False
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False