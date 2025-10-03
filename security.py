#!/usr/bin/env python3
"""
Security utilities for Project Revelare.
"""

import os
import re
import hashlib
import zipfile
import ipaddress
import logging
from typing import List, Tuple, Optional, Any
from pathlib import Path

from config import Config
from logger import get_logger, RevelareLogger 

logger = get_logger(__name__) 
security_logger = RevelareLogger.get_logger('security') 


class SecurityValidator:
    
    # --- Filename and Path Sanitization ---
    
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
            return False, Config.ERROR_MESSAGES.get('INVALID_INPUT', 'Project name cannot be empty')
        
        max_len = getattr(Config, 'MAX_PROJECT_NAME_LENGTH', 100)
        if len(project_name) > max_len:
            return False, f"Project name too long (max {max_len} characters)"
        
        if re.search(r'[<>:"/\\|?*]', project_name):
            security_logger.warning(f"Project name contains invalid characters: {project_name}")
            return False, Config.ERROR_MESSAGES.get('INVALID_INPUT', 'Project name contains invalid characters')
        
        if '..' in project_name or project_name.startswith('/'):
            security_logger.critical(f"Path traversal attempt in project name: {project_name}")
            return False, Config.ERROR_MESSAGES.get('PATH_TRAVERSAL', 'Project name contains traversal attempts')
        
        return True, Config.SUCCESS_MESSAGES.get('FILE_PROCESSED', 'Valid')
        
    @staticmethod
    def is_safe_path(target_path: str, base_path: Optional[str] = None) -> bool:
        """
        try:
            target_abs_path = Path(os.path.abspath(target_path)).resolve()
            
            # Check 1: Null Byte Injection
            if '\x00' in target_path:
                 security_logger.critical("Null byte injection attempt blocked.")
                 return False

            if base_path:
                # 2. Containment Check (Directory Traversal)
                base_abs_path = Path(os.path.abspath(base_path)).resolve()
                is_contained = str(target_abs_path).startswith(str(base_abs_path))
                if not is_contained:
                     security_logger.critical(f"Directory Traversal blocked. Target: {target_abs_path} is outside Base: {base_abs_path}")
                return is_contained
            
            # 3. Standalone Safety Check
            normalized_path = os.path.normpath(target_path)
            
            if normalized_path.startswith('..'):
                 security_logger.critical(f"Relative path traversal detected in file content: {target_path}")
                 return False
                 
            # 4. Path Length
            max_path_len = getattr(Config, 'MAX_FILE_PATH_LENGTH', 4096)
            if len(target_path) > max_path_len:
                 security_logger.warning(f"Path length exceeds limit: {target_path}")
                 return False
            
            return True
            
        except Exception as e:
            security_logger.error(f"Error during is_safe_path check: {e}")
            return False
            
    # --- File and Content Validation ---
    
    @staticmethod
    def validate_file_extension(filename: str) -> Tuple[bool, str]:
        if not filename:
            return False, Config.ERROR_MESSAGES.get('INVALID_INPUT', 'No filename provided')
        
        file_ext = os.path.splitext(filename)[1].lower()
        
        # CRITICAL FIX: Ensure Config.ALLOWED_EXTENSIONS is a dictionary before calling .values()
        if not isinstance(Config.ALLOWED_EXTENSIONS, dict):
             return False, "Configuration error: File extension list is malformed."
             
        # Flatten the dictionary of lists into a single set for efficient lookup
        all_allowed_exts = set(ext for exts in Config.ALLOWED_EXTENSIONS.values() for ext in exts)
        
        if file_ext not in all_allowed_exts:
            security_logger.warning(f"Blocked file with unsupported extension: {file_ext}")
            return False, f"File type {file_ext} not allowed"
        
        return True, Config.SUCCESS_MESSAGES.get('FILE_PROCESSED', 'Valid')
    
    @staticmethod
    def validate_file_size(file_path: str) -> Tuple[bool, str]:
        try:
            file_size = os.path.getsize(file_path)
            max_bytes = Config.MAX_CONTENT_LENGTH
            
            if file_size > max_bytes:
                security_logger.warning(f"Blocked file exceeding size limit: {file_size} bytes (max: {max_bytes})")
                max_mb = max_bytes // (1024*1024)
                return False, Config.ERROR_MESSAGES.get('FILE_TOO_LARGE', 'File too large').format(max_mb)
            return True, Config.SUCCESS_MESSAGES.get('FILE_PROCESSED', 'Valid')
        except OSError as e:
            return False, f"Cannot check file size: {str(e)}"
            
    # --- ZIP Security and Extraction ---
    
    @staticmethod
    def validate_zip_file(zip_path: str) -> Tuple[bool, str, List[str]]:
        max_files = getattr(Config, 'MAX_FILES_IN_ZIP', 10000)
        max_content = Config.MAX_CONTENT_LENGTH
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                file_infos = zip_file.infolist()
                file_count = len(file_infos)
                if file_count > max_files:
                    security_logger.critical(f"Zip Bomb (File Count) detected: {file_count} files.")
                    return False, Config.ERROR_MESSAGES.get('TOO_MANY_FILES', 'Too many files').format(max_files), []
                
                total_size = 0
                dangerous_files = []
                for file_info in file_infos:
                    if '..' in file_info.filename or Path(file_info.filename).is_absolute():
                        dangerous_files.append(file_info.filename)
                        
                    total_size += file_info.file_size
                
                if dangerous_files:
                    security_logger.critical(f"ZIP contains dangerous file paths (traversal): {dangerous_files[:5]}")
                    return False, Config.ERROR_MESSAGES.get('PATH_TRAVERSAL', 'Zip contains dangerous paths'), dangerous_files
                
                if total_size > max_content * 10: 
                    security_logger.critical(f"Zip Bomb (Size) detected: {total_size} bytes uncompressed.")
                    return False, "ZIP contents too large (decompression size limit exceeded)", []
                
                return True, Config.SUCCESS_MESSAGES.get('FILE_PROCESSED', 'Valid'), []
        
        except zipfile.BadZipFile:
            return False, "Invalid ZIP file format", []
        except Exception as e:
            return False, f"Error validating ZIP: {e}", []
    
    @staticmethod
    def safe_extract_zip(zip_path: str, extract_to: str) -> Tuple[bool, str]:
        try:
            import file_extractor
            return file_extractor.safe_extract_archive(zip_path, extract_to)
        except ImportError:
             return False, "file_extractor module not available for extraction."
        except Exception as e:
            return False, f"Extraction failed: {e}"


class InputValidator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_indicator_search(search_term: str) -> Tuple[bool, str]:
        max_len = getattr(Config, 'MAX_SEARCH_TERM_LENGTH', 1000)
        if not search_term or len(search_term) > max_len:
            return False, Config.ERROR_MESSAGES.get('INVALID_INPUT', 'Search term too long or empty')
        
        # Harden SQL injection checks
        dangerous_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|WAITFOR|CAST|SHUTDOWN)\b)',
            r'(\b(OR|AND)\s+\d+\s*=\s*\d+)',
            r'(--|;|\/\*|\*\/|\'|\")', # Trailing comments, semicolons, quotes
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, search_term, re.IGNORECASE):
                security_logger.critical(f"SQLi attempt blocked in search term: {search_term}")
                return False, Config.ERROR_MESSAGES.get('SECURITY_VIOLATION', 'Search term contains dangerous patterns')
        
        return True, Config.SUCCESS_MESSAGES.get('FILE_PROCESSED', 'Valid')
    
    @staticmethod
    def sanitize_html_input(text: str) -> str:
        if not text: return ""
        
        text = str(text)
        
        # 1. Remove dangerous content (scripts, tags)
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
        text = re.sub(r'<(?:/)?(?:script|iframe|object|embed|style|link|meta)[^>]*>', '', text, flags=re.IGNORECASE)

        # 2. Null Byte Check
        if '\x00' in text:
             security_logger.warning("Null byte detected and removed in HTML input.")
             text = text.replace('\x00', '')
             
        # 3. Escape HTML Special Characters (CRITICAL for XSS prevention)
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;').replace('/', '&#x2F;')
        
        # 4. Filter malicious protocols
        text = re.sub(r'j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:', '', text, flags=re.IGNORECASE)
        text = re.sub(r'd\s*a\s*t\s*a\s*:', '', text, flags=re.IGNORECASE)
        
        # 5. Length Limit
        max_html_len = getattr(Config, 'MAX_HTML_INPUT_LENGTH', 10000)
        if len(text) > max_html_len:
             text = text[:max_html_len] + "[...TRUNCATED...]"
        
        return text
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        if not ip: return False
            
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False