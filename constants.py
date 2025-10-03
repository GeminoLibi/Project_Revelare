#!/usr/bin/env python3
"""
Constants and configuration values for Project Revelare.

This module contains all the magic numbers, limits, and configuration
values used throughout the application. This centralizes configuration
and makes it easier to maintain and modify limits.
"""

# File and path limits
MAX_PROJECT_NAME_LENGTH = 100
MAX_FILENAME_LENGTH = 100
MAX_FILE_PATH_LENGTH = 260  # Windows path limit
MAX_SEARCH_TERM_LENGTH = 1000
MAX_HTML_INPUT_LENGTH = 10000
MAX_FILES_PER_UPLOAD = 100
MAX_FILES_IN_ZIP = 10000

# File processing limits
MAX_FILE_SIZE_MB = 100
CHUNK_SIZE = 4096  # For file reading
BINARY_CHUNK_SIZE = 1024  # For binary file scanning

# Large file processing
LARGE_FILE_THRESHOLD_MB = 10  # Files larger than this get chunked processing
MAX_CHUNK_SIZE_MB = 5  # Maximum chunk size for processing
CHUNK_OVERLAP_SIZE = 1024  # Overlap between chunks to catch split indicators
MAX_PROCESSING_TIME_SECONDS = 300  # 5 minutes max per file

# Monitoring and progress
PROGRESS_UPDATE_INTERVAL = 5  # Update progress every N files
MONITORING_INTERVAL_SECONDS = 10  # Log status every N seconds
REPORT_PROGRESS_INTERVAL = 100  # Update report progress every N indicators

# Nested ZIP processing
MAX_ZIP_DEPTH = 3  # Maximum nesting depth for ZIP files

# Forensic focus - indicators to prioritize
FORENSIC_INDICATORS = [
    'Email_Addresses', 'IPv4', 'IPv6', 'URLs', 'Phone_Numbers', 
    'Credit_Cards', 'Device_IDs_UUIDs', 'Email_Headers', 'User_Agents',
    'Firewall_Rules', 'Tokens', 'Process_Names', 'Connection_Info'
]

# Noisy indicators to filter out by default
NOISY_INDICATORS = [
    'ISO_Timestamps', 'Time_Formats', 'File_Paths', 'Unix_Timestamps',
    'Date_Formats', 'Log_Timestamps', 'Port_Numbers', 'IPv4_with_Port',
    'Packet_Info'
]

# Security limits
MAX_ZIP_DEPTH = 5  # Maximum ZIP nesting depth
MAX_EXTRACTED_FILES = 1000  # Maximum files to extract from ZIP

# Performance limits
MAX_IP_ENRICHMENT = 50  # Maximum IPs to enrich per request
RATE_LIMIT_DELAY = 0.1  # Delay between API calls (seconds)

# Logging limits
MAX_LOG_MESSAGE_LENGTH = 1000
MAX_LOG_ENTRIES = 10000

# Report limits
MAX_INDICATORS_PER_CATEGORY = 1000
MAX_REPORT_SIZE_MB = 50

# Database limits
MAX_DB_CONNECTIONS = 10
DB_TIMEOUT_SECONDS = 30

# Web interface limits
MAX_UPLOAD_SIZE_MB = 100
SESSION_TIMEOUT_MINUTES = 30
MAX_REQUESTS_PER_MINUTE = 60

# Error message templates
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

# Success message templates
SUCCESS_MESSAGES = {
    'FILE_PROCESSED': 'File processed successfully',
    'PROJECT_CREATED': 'Project created successfully',
    'REPORT_GENERATED': 'Report generated successfully',
    'EXPORT_COMPLETED': 'Export completed successfully'
}

# File type categories
ALLOWED_EXTENSIONS = {
    'text': ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm', '.yaml', '.yml', '.md', '.rst', '.tex', '.rtf', '.conf', '.cfg', '.ini', '.properties', '.env', '.gitignore', '.dockerignore'],
    'email': ['.eml', '.msg', '.mbox', '.mbx', '.pst', '.ost', '.dbx', '.tbb', '.emlx', '.nws', '.snm'],
    'documents': ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt', '.odt', '.ods', '.odp', '.pages', '.numbers', '.key', '.rtf', '.wpd', '.wps'],
    'archives': ['.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz', '.cab', '.deb', '.rpm', '.dmg', '.iso', '.img'],
    'data': ['.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.frm', '.myd', '.myi', '.ndb', '.ibd', '.dbf', '.db3'],
    'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.svg', '.ico', '.psd', '.raw', '.cr2', '.nef', '.dng'],
    'audio': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.aiff', '.au', '.ra', '.mid', '.midi'],
    'video': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.3gp', '.3g2', '.asf', '.rm', '.rmvb'],
    'executables': ['.exe', '.dll', '.sys', '.bat', '.cmd', '.com', '.scr', '.msi', '.app', '.deb', '.rpm'],
    'scripts': ['.py', '.js', '.php', '.rb', '.pl', '.sh', '.bash', '.ps1', '.vbs', '.asp', '.jsp', '.cgi'],
    'config': ['.ini', '.cfg', '.conf', '.config', '.xml', '.yaml', '.yml', '.json', '.toml', '.properties', '.env'],
    'logs': ['.log', '.txt', '.out', '.err', '.debug', '.trace', '.audit', '.syslog', '.eventlog'],
    'forensic': ['.evtx', '.evt', '.etl', '.pcap', '.pcapng', '.cap', '.ncap', '.hccap', '.hccapx', '.kismet', '.netxml'],
    'mobile': ['.apk', '.ipa', '.aab', '.plist', '.backup', '.itunes', '.android'],
    'virtualization': ['.vmdk', '.vhd', '.vhdx', '.vdi', '.qcow2', '.ova', '.ovf', '.vmx', '.vbox'],
    'compressed': ['.7z', '.zip', '.rar', '.tar', '.gz', '.bz2', '.xz', '.lz4', '.zst', '.lzma', '.ace', '.arj'],
    'system': ['.reg', '.inf', '.cat', '.cer', '.crt', '.pem', '.key', '.pfx', '.p12', '.jks', '.keystore']
}

# All supported formats combined for easy reference
ALL_SUPPORTED_FORMATS = []
for category, extensions in ALLOWED_EXTENSIONS.items():
    ALL_SUPPORTED_FORMATS.extend(extensions)

# Regex pattern categories
REGEX_CATEGORIES = [
    'IPv4', 'IPv6', 'Email_Addresses', 'URLs', 'File_Paths',
    'Credit_Cards', 'Phone_Numbers', 'MAC_Addresses', 'User_Agents',
    'Session_IDs', 'Cookies', 'Registry_Keys', 'Process_Names',
    'DNS_Queries', 'Network_Protocols'
]

# IP address ranges
PRIVATE_IP_RANGES = [
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16'
]

# Common irrelevant domains
IRRELEVANT_DOMAINS = [
    'example.com', 'test.com', 'demo.com', 'sample.com',
    'localhost', '127.0.0.1', '0.0.0.0'
]

# Common irrelevant file extensions
IRRELEVANT_EXTENSIONS = [
    '.tmp', '.temp', '.bak', '.backup', '.old', '.orig'
]

# Common irrelevant processes
IRRELEVANT_PROCESSES = [
    'notepad.exe', 'calc.exe', 'mspaint.exe', 'explorer.exe',
    'winlogon.exe', 'csrss.exe', 'services.exe', 'lsass.exe'
]
