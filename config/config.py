# config.py - Unified Configuration Management for Project Revelare
# Consolidates config.py and constants.py into a single, comprehensive configuration module

import os
from typing import Dict, List, Any

class Config:
    """Unified configuration management for Project Revelare"""
    
    # =============================================================================
    # APPLICATION SETTINGS
    # =============================================================================
    
    SECRET_KEY = os.environ.get('REVELARE_SECRET_KEY', 'revelare_v7_link_analysis_secure_key_2024')
    DEBUG = os.environ.get('REVELARE_DEBUG', 'False').lower() == 'true'
    HOST = os.environ.get('REVELARE_HOST', 'localhost')
    PORT = int(os.environ.get('REVELARE_PORT', '5000'))
    
    # =============================================================================
    # FILE PROCESSING SETTINGS
    # =============================================================================
    
    UPLOAD_FOLDER = os.environ.get('REVELARE_UPLOAD_FOLDER', os.path.join(os.path.dirname(__file__), '..', 'cases'))
    MAX_CONTENT_LENGTH = int(os.environ.get('REVELARE_MAX_FILE_SIZE', '2048')) * 1024 * 1024  # 2GB default
    MAX_FILE_SIZE = int(os.environ.get('REVELARE_MAX_FILE_SIZE', '2048')) * 1024 * 1024  # 2GB default
    
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
    BINARY_CHUNK_SIZE = 64 * 1024  # 64KB for binary file scanning (increased for better performance)

    # Archive processing - Intelligent chunking instead of hard limits
    ARCHIVE_BATCH_SIZE = 100  # Process files in batches of 100
    LARGE_ARCHIVE_THRESHOLD = 500  # Consider archive "large" if >500 files
    HUGE_ARCHIVE_THRESHOLD = 2000  # Consider archive "huge" if >2000 files
    MAX_FILE_SIZE_IN_ARCHIVE = 500 * 1024 * 1024  # 500MB max per file (increased for large data pulls)

    # Processing time estimates (seconds per MB, adjusted for file type)
    PROCESSING_RATES = {
        'text': 0.01,      # Very fast - 0.01 seconds per MB
        'binary': 0.05,    # Medium - 0.05 seconds per MB
        'archive': 2.0,    # Slow - nested archives take time
        'image': 0.1,      # Image processing
        'pdf': 0.2,        # PDF text extraction
        'unknown': 0.1     # Default fallback
    }
    
    # Large file processing
    LARGE_FILE_THRESHOLD_MB = 10  # Files larger than this get chunked processing
    MAX_CHUNK_SIZE_MB = 5  # Maximum chunk size for processing
    CHUNK_OVERLAP_SIZE = 1024  # Overlap between chunks to catch split indicators
    MAX_PROCESSING_TIME_SECONDS = 300  # 5 minutes max per file
    MAX_TEXT_SIZE_FOR_PROCESSING = 50 * 1024 * 1024  # 50MB max text size for regex processing
    
    # Monitoring and progress
    PROGRESS_UPDATE_INTERVAL = 5  # Update progress every N files
    MONITORING_INTERVAL_SECONDS = 10  # Log status every N seconds
    REPORT_PROGRESS_INTERVAL = 100  # Update report progress every N indicators
    
    # Nested ZIP processing
    MAX_ZIP_DEPTH = 3  # Maximum nesting depth for ZIP files
    
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
    
    # =============================================================================
    # FILE TYPE CONFIGURATION
    # =============================================================================
    
    # Comprehensive file type categories (consolidated from constants.py)
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
    
    # File Type Mappings (legacy compatibility)
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
    
    # =============================================================================
    # DATABASE SETTINGS
    # =============================================================================
    
    DATABASE = os.environ.get('REVELARE_DATABASE', os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'revelare_master.db'))
    
    # =============================================================================
    # SECURITY SETTINGS
    # =============================================================================
    
    SANITIZE_FILENAMES = True
    
    # =============================================================================
    # API SETTINGS
    # =============================================================================
    
    IP_API_RATE_LIMIT = 0.5  # seconds between requests
    IP_API_TIMEOUT = 10  # seconds
    IP_API_RETRIES = 3
    
    # =============================================================================
    # REGEX PATTERNS FOR INDICATOR EXTRACTION
    # =============================================================================
    
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
        
        # Financial and personal data - Enhanced with better validation
        'SSN': r'\b(?!000|666|9\d{2})\d{3}[-](?!00)\d{2}[-](?!0000)\d{4}\b(?!\d)',  # More specific SSN pattern (requires dashes)
        'SSN_with_dots': r'\b(?!000|666|9\d{2})\d{3}\.\d{2}\.\d{4}\b(?!\d)',  # SSN with dots
        'Phone_Numbers': r'\b(?:\+?1[-.\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b(?!\d)',
        'US_Zip_Codes': r'\b\d{5}(?:-\d{4})?\b(?!\d)',  # 5 or 9 digit zip codes

        # Credit card numbers with various formatting (16 digits with dashes/spaces)
        'Credit_Card_Numbers': r'\b(?:\d{4}[-\s]){3}\d{4}|\d{16}\b(?!\d)',  # 16-digit cards with dashes/spaces or continuous
        'Credit_Card_Amex': r'\b(?:\d{4}[-\s]){2}\d{6}|\d{15}\b(?!\d)',  # Amex format (15 digits)
        'Credit_Card_Diners': r'\b(?:\d{4}[-\s]){2}\d{6}|\d{14}\b(?!\d)',  # Diners format (14 digits)

        'Bank_Account_Numbers': r'\b\d{8,12}\b(?!\d)',  # 8-12 digit account numbers (more realistic range)
        'Routing_Numbers': r'\b\d{9}\b(?!\d)',  # 9-digit routing numbers
        'Driver_License': r'\b[A-Z]\d{6,8}\b(?!\d)',  # Various DL formats
        'Passport_Numbers': r'\b[A-Z]{1,2}\d{7,8}\b(?!\d)',  # Passport formats (require letter prefix)
        'Tax_ID': r'\b\d{2}-\d{7}\b(?!\d)',  # EIN format
        'VIN': r'\b[A-HJ-NPR-Z0-9]{17}\b(?!\d)',  # Vehicle Identification Number

        # Medical and healthcare data - Enhanced validation (reject all zeros)
        'Medical_Record_Numbers': r'\bMRN[-]?(?!0{6,10})\d{6,10}\b|\b(?!0{8,12})\d{8,12}\b(?!\d)',  # Medical Record Numbers (reject all zeros)
        'Prescription_Numbers': r'\bRX\d{10,15}\b',  # Prescription numbers
        'Insurance_Policy_Numbers': r'\b\d{10}(?:\d{2})?\b(?!\d)',  # Insurance policy numbers

        # Structured data patterns (look for labels followed by data)
        'Account_Number_Patterns': r'\b(?:Account\s+Number|Acct\s+Num|Account\s+#|Acct\s+#)[\s:-]*([A-Z0-9]{8,20})\b',
        'First_Name_Patterns': r'\b(?:First\s+Name|First\s+Name:|F\s+Name)[\s:-]*([A-Za-z\s]{2,50})\b',
        'Last_Name_Patterns': r'\b(?:Last\s+Name|Last\s+Name:|L\s+Name|Surname)[\s:-]*([A-Za-z\s]{2,50})\b',
        'Email_Address_Patterns': r'\b(?:Email|Email\s+Address|E-mail|E-mail\s+Address)[\s:-]*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
        'Phone_Number_Patterns': r'\b(?:Phone|Phone\s+Number|Telephone|Mobile|Cell)[\s:-]*([\(\)\d\s\-\.\+]{7,20})\b',
        'Address_Patterns': r'\b(?:Address|Street\s+Address|Home\s+Address)[\s:-]*([A-Za-z0-9\s,.-]{10,100})\b',
        'DOB_Patterns': r'\b(?:DOB|Date\s+of\s+Birth|Birth\s+Date|Birthday)[\s:-]*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b',
        'SSN_Patterns': r'\b(?:SSN|Social\s+Security|Social\s+Security\s+Number)[\s:-]*(\d{3}[-.]?\d{2}[-.]?\d{4})\b'
    }

    # =============================================================================
    # EXTRACTION CONTROL
    # =============================================================================

    # Bank routing number database for verification
    ROUTING_NUMBERS = {
        # Major banks (sample - in production, this would be much more comprehensive)
        '021000021': 'JPMorgan Chase Bank',
        '021000021': 'JPMorgan Chase Bank, N.A.',
        '031100173': 'Bank of America, N.A.',
        '031100173': 'Bank of America',
        '051000017': 'Citibank, N.A.',
        '051000017': 'Citibank',
        '051000017': 'Citigroup',
        '051000017': 'Citi',
        '021000021': 'Chase',
        '031100173': 'BOA',
        '031100173': 'Bank of America',
        '031100173': 'BofA',
        '053000219': 'The Bank of New York Mellon',
        '053000219': 'BNY Mellon',
        '021000021': 'JPMorgan',
        '021000021': 'JP Morgan',
        '021000021': 'J.P. Morgan',
        '031100173': 'Bank of America Corporation',
        '031100173': 'BAC',
        '051000017': 'Citigroup Inc.',
        '051000017': 'C',
        # Add more as needed - this is just a sample
        '011000015': 'Federal Reserve Bank',
        '011000015': 'Fed',
        '011000015': 'Federal Reserve',
        '021000021': 'JPMorgan Chase & Co.',
        '021000021': 'JPMC',
        '031100173': 'Bank of America Corporation',
        '051000017': 'Citigroup Global Markets Inc.',
        '053000219': 'BNY Mellon, N.A.',
        '053000219': 'The Bank of New York',
        '053000219': 'Mellon Bank',
        '021000021': 'Chase Manhattan Bank',
        '021000021': 'Chemical Bank',
        '031100173': 'NationsBank',
        '031100173': 'NCNB',
        '051000017': 'First National City Bank',
        '051000017': 'Citizens & Southern National Bank',
        '053000219': 'Mellon Financial Corporation',
        '053000219': 'Mellon',
        '021000021': 'Manufacturers Hanover Trust Company',
        '021000021': 'Chemical Banking Corporation',
        '031100173': 'Barnett Banks, Inc.',
        '031100173': 'Barnett Bank',
        '051000017': 'First National City Bank of New York',
        '051000017': 'Citizens & Southern',
        '053000219': 'BNY',
        '053000219': 'Mellon National Bank',
        # Federal Reserve Banks
        '010000000': 'Federal Reserve Bank of Boston',
        '011000000': 'Federal Reserve Bank of New York',
        '012000000': 'Federal Reserve Bank of Philadelphia',
        '013000000': 'Federal Reserve Bank of Cleveland',
        '014000000': 'Federal Reserve Bank of Richmond',
        '015000000': 'Federal Reserve Bank of Atlanta',
        '016000000': 'Federal Reserve Bank of Chicago',
        '017000000': 'Federal Reserve Bank of St. Louis',
        '018000000': 'Federal Reserve Bank of Minneapolis',
        '019000000': 'Federal Reserve Bank of Kansas City',
        '020000000': 'Federal Reserve Bank of Dallas',
        '021000000': 'Federal Reserve Bank of San Francisco',
        # Test routing numbers (commonly used in software testing)
        '011000015': 'Federal Reserve Bank of New York',
        '021000021': 'JPMorgan Chase Bank, N.A.',
        '031100173': 'Bank of America, N.A.',
        '051000017': 'Citibank, N.A.',
        '053000219': 'The Bank of New York Mellon',
        '061000052': 'Bank of America, N.A.',
        '071000013': 'JPMorgan Chase Bank, N.A.',
        '081000032': 'Bank of America, N.A.',
        '091000019': 'JPMorgan Chase Bank, N.A.',
        '101000019': 'Bank of America, N.A.',
        '111000038': 'JPMorgan Chase Bank, N.A.',
        '121000248': 'JPMorgan Chase Bank, N.A.',
        '131000000': 'Federal Reserve Bank of Philadelphia',
        '141000000': 'Federal Reserve Bank of Cleveland',
        '151000000': 'Federal Reserve Bank of Richmond',
        '161000000': 'Federal Reserve Bank of Atlanta',
        '171000000': 'Federal Reserve Bank of Chicago',
        '181000000': 'Federal Reserve Bank of St. Louis',
        '191000000': 'Federal Reserve Bank of Minneapolis',
        '201000000': 'Federal Reserve Bank of Kansas City',
        '211000000': 'Federal Reserve Bank of Dallas',
        '221000000': 'Federal Reserve Bank of San Francisco',
        # Major commercial banks
        '011000015': 'Wells Fargo Bank, N.A.',
        '011000015': 'Wells Fargo',
        '011000015': 'WFC',
        '021000021': 'Bank of America, N.A.',
        '031100173': 'Citibank, N.A.',
        '051000017': 'JPMorgan Chase Bank, N.A.',
        '053000219': 'U.S. Bank National Association',
        '053000219': 'U.S. Bank',
        '053000219': 'USB',
        '061000052': 'PNC Bank, National Association',
        '061000052': 'PNC Bank',
        '061000052': 'PNC',
        '071000013': 'Capital One, National Association',
        '071000013': 'Capital One',
        '071000013': 'COF',
        '081000032': 'TD Bank, National Association',
        '081000032': 'TD Bank',
        '091000019': 'SunTrust Bank',
        '091000019': 'SunTrust',
        '091000019': 'STI',
        '101000019': 'Regions Bank',
        '101000019': 'Regions',
        '101000019': 'RF',
        '111000038': 'Fifth Third Bank',
        '111000038': 'Fifth Third',
        '111000038': 'FITB',
        '121000248': 'KeyBank National Association',
        '121000248': 'KeyBank',
        '121000248': 'KEY',
        '131000000': 'BB&T',
        '131000000': 'BBT',
        '141000000': 'Huntington National Bank',
        '141000000': 'Huntington',
        '141000000': 'HBAN',
        '151000000': 'Santander Bank, N.A.',
        '151000000': 'Santander',
        '161000000': 'Branch Banking & Trust Company',
        '161000000': 'BB&T Corporation',
        '171000000': 'Ally Bank',
        '171000000': 'Ally',
        '171000000': 'ALLY',
        '181000000': 'Discover Bank',
        '181000000': 'Discover',
        '181000000': 'DFS',
        '191000000': 'USAA Federal Savings Bank',
        '191000000': 'USAA',
        '201000000': 'American Express',
        '201000000': 'Amex',
        '201000000': 'AXP',
        '211000000': 'Capital One Bank (USA), National Association',
        '221000000': 'Navy Federal Credit Union',
        '221000000': 'NFCU',
    }
    
    # =============================================================================
    # EXTRACTION CONTROL
    # =============================================================================
    
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
    
    # =============================================================================
    # FILTERING PATTERNS
    # =============================================================================
    
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
    
    # =============================================================================
    # FORENSIC INDICATORS
    # =============================================================================
    
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
    
    # Regex pattern categories
    REGEX_CATEGORIES = [
        'IPv4', 'IPv6', 'Email_Addresses', 'URLs', 'File_Paths',
        'Credit_Cards', 'Phone_Numbers', 'MAC_Addresses', 'User_Agents',
        'Session_IDs', 'Cookies', 'Registry_Keys', 'Process_Names',
        'DNS_Queries', 'Network_Protocols'
    ]
    
    # =============================================================================
    # NETWORK CONFIGURATION
    # =============================================================================
    
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
    
    # =============================================================================
    # LOGGING CONFIGURATION
    # =============================================================================
    
    LOG_LEVEL = os.environ.get('REVELARE_LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # =============================================================================
    # MESSAGE TEMPLATES
    # =============================================================================
    
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
    
    # =============================================================================
    # UTILITY METHODS
    # =============================================================================
    
    @classmethod
    def validate_config(cls) -> List[str]:
        """Validate configuration and return any errors"""
        errors = []

        # Check if upload folder exists or can be created
        try:
            os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
            # Test if we can write to the directory
            test_file = os.path.join(cls.UPLOAD_FOLDER, '.config_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except Exception as e:
            errors.append(f"Cannot create or write to upload folder '{cls.UPLOAD_FOLDER}': {e}")

        # Validate port number
        if not isinstance(cls.PORT, int) or not (1 <= cls.PORT <= 65535):
            errors.append(f"Invalid port number: {cls.PORT} (must be integer between 1-65535)")

        # Validate max content length
        if not isinstance(cls.MAX_CONTENT_LENGTH, int) or cls.MAX_CONTENT_LENGTH <= 0:
            errors.append(f"Invalid max content length: {cls.MAX_CONTENT_LENGTH} (must be positive integer)")

        # Validate file size limits
        if cls.MAX_FILE_SIZE_MB <= 0:
            errors.append(f"Invalid max file size: {cls.MAX_FILE_SIZE_MB}MB (must be positive)")

        # Validate regex patterns
        for category, pattern in cls.REGEX_PATTERNS.items():
            try:
                import re
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                errors.append(f"Invalid regex pattern for {category}: {e}")

        # Validate log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if cls.LOG_LEVEL.upper() not in valid_log_levels:
            errors.append(f"Invalid log level '{cls.LOG_LEVEL}'. Must be one of: {', '.join(valid_log_levels)}")

        return errors
    
    # =============================================================================
    # EMAIL SETTINGS
    # =============================================================================

    # SMTP Configuration
    SMTP_SERVER = os.environ.get('REVELARE_SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('REVELARE_SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('REVELARE_SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('REVELARE_SMTP_PASSWORD', '')
    SMTP_USE_TLS = os.environ.get('REVELARE_SMTP_USE_TLS', 'True').lower() == 'true'
    SMTP_USE_SSL = os.environ.get('REVELARE_SMTP_USE_SSL', 'False').lower() == 'true'

    # IMAP Configuration
    IMAP_SERVER = os.environ.get('REVELARE_IMAP_SERVER', 'imap.gmail.com')
    IMAP_PORT = int(os.environ.get('REVELARE_IMAP_PORT', '993'))
    IMAP_USERNAME = os.environ.get('REVELARE_IMAP_USERNAME', '')
    IMAP_PASSWORD = os.environ.get('REVELARE_IMAP_PASSWORD', '')

    # Email Settings
    DEFAULT_FROM_EMAIL = os.environ.get('REVELARE_FROM_EMAIL', 'noreply@project-revelare.com')
    SUPPORT_EMAIL = os.environ.get('REVELARE_SUPPORT_EMAIL', 'support@project-revelare.com')
    ADMIN_EMAIL = os.environ.get('REVELARE_ADMIN_EMAIL', 'admin@project-revelare.com')

    # Email Limits
    MAX_EMAIL_SIZE_MB = int(os.environ.get('REVELARE_MAX_EMAIL_SIZE_MB', '25'))
    MAX_ATTACHMENTS_PER_EMAIL = int(os.environ.get('REVELARE_MAX_ATTACHMENTS', '10'))
    MAX_ATTACHMENT_SIZE_MB = int(os.environ.get('REVELARE_MAX_ATTACHMENT_SIZE_MB', '10'))

    # Email Templates
    EMAIL_TEMPLATES = {
        'welcome': {
            'subject': 'Welcome to Project Revelare',
            'body': '''Welcome to Project Revelare!

Thank you for your interest in our advanced digital forensics platform.

Project Revelare is a comprehensive tool for:
- Digital evidence analysis and extraction
- IOC (Indicators of Compromise) identification
- Advanced reporting and documentation
- OCR and speech-to-text processing

To get started:
1. Download the latest version from our website
2. Run the onboarding wizard
3. Start analyzing your digital evidence

Visit our documentation at: https://docs.project-revelare.com

Best regards,
The Project Revelare Team'''
        },
        'support_response': {
            'subject': 'Re: Your Support Request',
            'body': '''Thank you for contacting Project Revelare support.

We have received your message and will respond within 24-48 hours.

In the meantime, you might find answers to common questions in our documentation:
https://docs.project-revelare.com/faq

Best regards,
Project Revelare Support Team'''
        }
    }

    @classmethod
    def get_database_url(cls) -> str:
        """Get database URL for SQLAlchemy if needed in future"""
        return f"sqlite:///{cls.DATABASE}"
    
    @classmethod
    def get_supported_file_types(cls) -> List[str]:
        """Get list of supported file extensions"""
        return list(cls.ALLOWED_EXTENSIONS)
    
    @classmethod
    def get_all_supported_formats(cls) -> List[str]:
        """Get all supported file formats as a flat list"""
        return cls.ALL_SUPPORTED_FORMATS
    
    @classmethod
    def is_file_type_allowed(cls, file_extension: str) -> bool:
        """Check if a file extension is allowed"""
        return file_extension.lower() in cls.ALL_SUPPORTED_FORMATS
    
    @classmethod
    def get_file_category(cls, file_extension: str) -> str:
        """Get the category for a file extension"""
        file_ext = file_extension.lower()
        for category, extensions in cls.ALLOWED_EXTENSIONS.items():
            if file_ext in extensions:
                return category
        return 'unknown'
