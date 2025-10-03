#!/usr/bin/env python3
"""
Centralized logging system for Project Revelare.
"""

import logging
import sys
import os
from typing import Optional, Dict, Any
from config import Config 

class RevelareLogger:
    
    _instance: Optional['RevelareLogger'] = None
    _logger: Optional[logging.Logger] = None
    _is_setup = False
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._is_setup:
            self._setup_logger()
            RevelareLogger._is_setup = True
    
    def _setup_logger(self):
        
        # 1. Base Logger Configuration
        self._logger = logging.getLogger('revelare') 
        log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
        self._logger.setLevel(log_level)
        self._logger.propagate = False
        
        # Clear any existing handlers
        if self._logger.handlers:
            for handler in self._logger.handlers:
                self._logger.removeHandler(handler)
        
        # 2. Formatter
        formatter = logging.Formatter(Config.LOG_FORMAT)
        
        # 3. Handlers
        
        # Console Handler (Outputs all INFO+ logs to stdout)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO if log_level < logging.INFO else log_level)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)
        
        # File Handler (Audit Log - DEBUG level for full audit trail)
        try:
            log_file_path = os.environ.get('REVELARE_LOG_FILE', 'revelare_audit.log')
            file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG) 
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)
        except Exception as e:
            self._logger.warning(f"Could not setup file logging to '{log_file_path}': {e}")

    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        
        If 'name' is provided, returns a sub-logger (e.g., 'revelare.extractor').
        If 'name' is None, returns the root 'revelare' logger.
        """
        # FIX: Returns the correctly named logger instance
        if name:
            return logging.getLogger(f'revelare.{name}')
        return self._logger

    # --- Specialized Logging Methods ---

    def log_file_processing(self, file_path: str, status: str, error: Optional[str] = None):
        logger = self.get_logger('file_processor')
        if status == 'success':
            logger.info(f"File Processed [SUCCESS]: {file_path}")
        elif status == 'error':
            logger.error(f"File Processing [FAILURE]: {file_path}. Error: {error}")
        elif status == 'skipped':
            logger.warning(f"File Processed [SKIPPED]: {file_path}. Reason: Unsupported type or access denied.")

    def log_performance(self, operation: str, duration: float, details: Optional[Dict[str, Any]] = None):
        logger = self.get_logger('performance')
        details_str = f"| Details: {details}" if details else ""
        
        if duration >= 5.0:
            logger.warning(f"PERF ALERT [SLOW]: '{operation}' took {duration:.2f}s {details_str}")
        elif duration >= 0.5:
            logger.info(f"PERF INFO [MEDIUM]: '{operation}' took {duration:.2f}s {details_str}")
        else:
            logger.debug(f"PERF DEBUG [FAST]: '{operation}' completed in {duration:.2f}s {details_str}")
            
    def log_api_request(self, api_name: str, endpoint: str, status_code: int, response_time: float):
        logger = self.get_logger('api_client')
        
        if 200 <= status_code < 300:
            logger.debug(f"API Request [SUCCESS]: {api_name} to {endpoint} Status={status_code} ({response_time:.2f}s)")
        else:
            logger.error(f"API Request [FAILURE]: {api_name} to {endpoint} Status={status_code} ({response_time:.2f}s)")

    def log_security_event(self, event_type: str, details: str, severity: str = 'medium'):
        logger = self.get_logger('security')
        log_message = f"SECURITY EVENT [{event_type.upper()}]: {details}"
        if severity == 'high':
            logger.critical(log_message)
        elif severity == 'medium':
            logger.warning(log_message)
        else:
            logger.info(log_message)


# --- Global Access Functions (FIXED) ---

# Initialize the Singleton instance
revelare_logger_instance = RevelareLogger()

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return revelare_logger_instance.get_logger(name)

# Expose the specialized logger methods through a convenient global instance
RevelareLogger = revelare_logger_instance