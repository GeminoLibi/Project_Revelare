import logging
import sys
import os
from typing import Optional, Dict, Any
from revelare.config.config import Config 

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
        self._logger = logging.getLogger('revelare') 
        log_level = getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO)
        self._logger.setLevel(log_level)
        self._logger.propagate = False
        
        if self._logger.handlers:
            for handler in self._logger.handlers:
                self._logger.removeHandler(handler)
        
        formatter = logging.Formatter(Config.LOG_FORMAT)
        
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)
        
        try:
            log_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            log_file_path = os.path.join(log_dir, 'revelare_audit.log')
            
            file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG) 
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)
        except Exception as e:
            self._logger.warning(f"Could not setup file logging: {e}")

    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        if name:
            return logging.getLogger(f'revelare.{name}')
        return self._logger

    def log_security_event(self, event_type: str, details: str, severity: str = 'medium'):
        logger = self.get_logger('security')
        log_message = f"SECURITY EVENT [{event_type.upper()}]: {details}"
        if severity == 'high':
            logger.critical(log_message)
        elif severity == 'medium':
            logger.warning(log_message)
        else:
            logger.info(log_message)

revelare_logger_instance = RevelareLogger()

def get_logger(name: Optional[str] = None) -> logging.Logger:
    return revelare_logger_instance.get_logger(name)

RevelareLogger = revelare_logger_instance