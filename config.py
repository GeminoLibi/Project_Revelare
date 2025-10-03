# config.py - Configuration Management for Project Revelare

import os
from typing import Dict, List, Any

class Config:
    """Configuration management for Project Revelare"""
    
    # Application Settings
    SECRET_KEY = os.environ.get('REVELARE_SECRET_KEY', 'revelare_v7_link_analysis_secure_key_2024')
    DEBUG = os.environ.get('REVELARE_DEBUG', 'False').lower() == 'true'
    HOST = os.environ.get('REVELARE_HOST', 'localhost')
    PORT = int(os.environ.get('REVELARE_PORT', '5000'))
    
    # File Processing Settings
    UPLOAD_FOLDER = os.environ.get('REVELARE_UPLOAD_FOLDER', 'projects')
    MAX_CONTENT_LENGTH = int(os.environ.get('REVELARE_MAX_FILE_SIZE', '2048')) * 1024 * 1024  # 2GB default
    MAX_FILE_SIZE = int(os.environ.get('REVELARE_MAX_FILE_SIZE', '2048')) * 1024 * 1024  # 2GB default
    ALLOWED_EXTENSIONS = {'.zip', '.pdf', '.docx', '.xlsx', '.txt', '.json', '.csv', '.xml', '.html', '.htm', '.mbox'}
    
    # Database Settings
    DATABASE = os.environ.get('REVELARE_DATABASE', 'revelare_master.db')
    
    # Security Settings
    MAX_FILENAME_LENGTH = 255
    SANITIZE_FILENAMES = True
    
    # API Settings
    IP_API_RATE_LIMIT = 0.5  # seconds between requests
    IP_API_TIMEOUT = 10  # seconds
    IP_API_RETRIES = 3
    
    # Regex Patterns for Indicator Extraction - Enhanced for Legal Warrant Requirements
    REGEX_PATTERNS = {
        # IP Addresses with port information
        'IPv4_with_Port': r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):(\d{1,5})\b',
        'IPv4': r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'IPv6_with_Port': r'\[([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]:(\d{1,5})',
        'IPv6': r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
        
        # Email addresses with enhanced patterns - only complete emails
        'Email_Addresses': r'\b[a-zA-Z0-9]([a-zA-Z0-9._%-]*[a-zA-Z0-9])?@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b',
        
        # URLs with enhanced patterns
        'URLs': r'\bhttps?://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+(?::\d{1,5})?(?:/[^\s]*)?\b',
        'URLs_with_Ports': r'\bhttps?://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+:\d{1,5}(?:/[^\s]*)?\b',
        'FTP_URLs': r'\bftp://[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+(?::\d{1,5})?(?:/[^\s]*)?\b',
        'File_URLs': r'\bfile://[^\s]+\b',
        
        # Timestamps and dates (crucial for legal warrants)
        'ISO_Timestamps': r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d{3})?([+-]\d{2}:\d{2}|Z)?',
        'Unix_Timestamps': r'\b\d{10}(\.\d{3})?\b',
        'HTTP_Timestamps': r'(Date|Last-Modified|Expires):\s*[A-Za-z]{3},\s*\d{2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+GMT',
        'Log_Timestamps': r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        'Date_Formats': r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b',
        'Time_Formats': r'\b\d{1,2}:\d{2}(:\d{2})?(\s*[AaPp][Mm])?\b',
        
        # Network and connection data
        'Device_IDs_UUIDs': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'MAC_Addresses': r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})',
        'Port_Numbers': r':(\d{1,5})\b',
        'Protocol_Headers': r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^\s]+\s+HTTP/\d\.\d',
        'User_Agents': r'User-Agent:\s*[^\r\n]+',
        'Host_Headers': r'Host:\s*[^\r\n]+',
        'Connection_Info': r'Connection:\s*[^\r\n]+',
        
        # Financial and personal data
        'SSN': r'\b(?!000|666|9\d{2})\d{3}[-.]?(?!00)\d{2}[-.]?(?!0000)\d{4}\b',
        'Phone_Numbers': r'\b(?:\+?1[-.\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b',
        
        # File and system information
        'File_Paths': r'[A-Za-z]:[\\/][^\r\n\s]+|/[^\r\n\s]+',
        'Process_Names': r'[A-Za-z0-9_\-\.]+\.(exe|dll|sys|bat|cmd|ps1)',
        'Registry_Keys': r'HKEY_[A-Z_]+\\[^\r\n\s]+',
        
        # Network traffic patterns
        'Packet_Info': r'(src|dst|sport|dport|proto):\s*[^\s]+',
        'Firewall_Rules': r'(allow|deny|drop|reject)\s+[^\r\n]+',
        'DNS_Queries': r'query:\s*[^\s]+\s+type\s+[A-Z]+',
        
        # Session and authentication data
        'Session_IDs': r'[Ss]ession[_-]?[Ii][Dd]:\s*[A-Za-z0-9+/=]+',
        'Cookies': r'[Cc]ookie:\s*[^\r\n]+',
        'Tokens': r'[Tt]oken:\s*[A-Za-z0-9+/=]+',
        'API_Keys': r'[Aa]pi[_-]?[Kk]ey:\s*[A-Za-z0-9+/=]+',
    }
    
    # Granular extraction control - what to extract by default
    EXTRACTION_CATEGORIES = {
        'IPv4': True,
        'IPv6': True,
        'Email_Addresses': True,
        'URLs': True,
        'Phone_Numbers': True,
        'SSN': True,
        'Device_IDs_UUIDs': True,
        'MAC_Addresses': True,
        'User_Agents': True,
        'Process_Names': True,
        'File_Paths': False,  # Usually too noisy
        'ISO_Timestamps': False,  # Usually too noisy
        'Unix_Timestamps': False,  # Usually too noisy
        'HTTP_Timestamps': False,  # Usually too noisy
        'Log_Timestamps': False,  # Usually too noisy
        'Date_Formats': False,  # Usually too noisy
        'Time_Formats': False,  # Usually too noisy
        'Port_Numbers': False,  # Usually too noisy
        'Protocol_Headers': False,  # Usually too noisy
        'Host_Headers': False,  # Usually too noisy
        'Connection_Info': False,  # Usually too noisy
        'Firewall_Rules': False,  # Usually too noisy
        'DNS_Queries': False,  # Usually too noisy
        'Session_IDs': False,  # Usually too noisy
        'Cookies': False,  # Usually too noisy
        'Tokens': False,  # Usually too noisy
        'API_Keys': False,  # Usually too noisy
        'Registry_Keys': False,  # Usually too noisy
        'Packet_Info': False,  # Usually too noisy
    }
    
    # Filtering patterns for irrelevant data
    FILTER_PATTERNS = {
        'Common_Irrelevant_IPs': [
            r'^127\.0\.0\.1$',  # localhost
            r'^0\.0\.0\.0$',    # all interfaces
            r'^255\.255\.255\.255$',  # broadcast
            r'^169\.254\.',     # link-local
            r'^224\.',          # multicast
            r'^240\.',          # reserved
        ],
        'Common_Irrelevant_URLs': [
            r'^https?://localhost',
            r'^https?://127\.0\.0\.1',
            r'^https?://0\.0\.0\.0',
            r'^file://',
            r'^data:',
            r'^javascript:',
            r'^mailto:',
        ],
        'Common_Irrelevant_Emails': [
            r'^[^a-zA-Z0-9]',  # Starts with punctuation
            r'^noreply@',
            r'^no-reply@',
            r'^donotreply@',
            r'^admin@localhost',
            r'^test@',
            r'^example@',
            r'^abuse@',
            r'^spam@',
            r'^postmaster@',
            r'^mailer-daemon@',
            r'^bounce@',
            r'^nobody@',
            r'^root@',
            r'^daemon@',
            r'^system@',
            r'^automated@',
            r'^auto@',
            r'^notification@',
            r'^alerts@',
            r'^notifications@',
            r'^newsletter@',
            r'^marketing@',
            r'^promo@',
            r'^support@',
            r'^help@',
            r'^info@',
            r'^contact@',
            r'^sales@',
            r'^billing@',
            r'^accounts@',
            r'^admin@',
            r'^administrator@',
            r'^webmaster@',
            r'^hostmaster@',
            r'^listmaster@',
            r'^owner@',
            r'^moderator@',
            r'^unsubscribe@',
            r'^opt-out@',
            r'^optout@',
        ],
        'Common_Irrelevant_Ports': [
            r':80$',    # HTTP
            r':443$',   # HTTPS
            r':22$',    # SSH
            r':21$',    # FTP
            r':25$',    # SMTP
            r':53$',    # DNS
            r':110$',   # POP3
            r':143$',   # IMAP
            r':993$',   # IMAPS
            r':995$',   # POP3S
        ]
    }
    
    # File Type Mappings
    FILE_TYPE_MAPPINGS = {
        '.txt': 'text',
        '.json': 'text',
        '.csv': 'text',
        '.xml': 'text',
        '.html': 'text',
        '.htm': 'text',
        '.pdf': 'pdf',
        '.docx': 'docx',
        '.xlsx': 'xlsx',
        '.mbox': 'mbox',
    }
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('REVELARE_LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Error and Success Messages
    ERROR_MESSAGES = {
        'FILE_TOO_LARGE': 'File too large (max {}MB)',
        'TOO_MANY_FILES': 'Too many files (max {})',
        'INVALID_FILE_TYPE': 'File type not allowed',
        'PATH_TRAVERSAL': 'Path traversal detected',
        'FILE_NOT_FOUND': 'File not found',
        'PERMISSION_DENIED': 'Permission denied',
        'INVALID_INPUT': 'Invalid input provided',
        'PROCESSING_ERROR': 'Error processing file',
        'SECURITY_VIOLATION': 'Security validation failed'
    }
    
    SUCCESS_MESSAGES = {
        'FILE_PROCESSED': 'File processed successfully',
        'PROJECT_CREATED': 'Project created successfully',
        'REPORT_GENERATED': 'Report generated successfully',
        'EXPORT_COMPLETED': 'Export completed successfully'
    }
    
    @classmethod
    def validate_config(cls) -> List[str]:
        """Validate configuration and return any errors"""
        errors = []
        
        # Check if upload folder exists or can be created
        try:
            os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create upload folder: {e}")
        
        # Validate port number
        if not (1 <= cls.PORT <= 65535):
            errors.append(f"Invalid port number: {cls.PORT}")
        
        # Validate max content length
        if cls.MAX_CONTENT_LENGTH <= 0:
            errors.append(f"Invalid max content length: {cls.MAX_CONTENT_LENGTH}")
        
        return errors
    
    @classmethod
    def get_database_url(cls) -> str:
        """Get database URL for SQLAlchemy if needed in future"""
        return f"sqlite:///{cls.DATABASE}"
    
    @classmethod
    def get_supported_file_types(cls) -> List[str]:
        """Get list of supported file extensions"""
        return list(cls.ALLOWED_EXTENSIONS)
