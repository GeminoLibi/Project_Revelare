import os
from typing import Dict, List, Any

def load_env_file(env_path: str = None) -> None:
    """Load environment variables from .env file"""
    if env_path is None:
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

# Load .env file if it exists
load_env_file()

class Config:
    SECRET_KEY = os.environ.get('REVELARE_SECRET_KEY', 'revelare_v7_link_analysis_secure_key_2024')
    DEBUG = os.environ.get('REVELARE_DEBUG', 'False').lower() == 'true'
    HOST = os.environ.get('REVELARE_HOST', '127.0.0.1')
    PORT = int(os.environ.get('REVELARE_PORT', '5000'))
    
    UPLOAD_FOLDER = os.environ.get('REVELARE_UPLOAD_FOLDER', os.path.join(os.path.dirname(__file__), '..', '..', 'cases'))
    MAX_CONTENT_LENGTH = None  # No limit - set to None to allow unlimited file sizes
    BINARY_CHUNK_SIZE = int(os.environ.get('REVELARE_BINARY_CHUNK_SIZE', '8192'))
    
    DATABASE = os.environ.get('REVELARE_DATABASE', os.path.join(os.path.dirname(__file__), '..', '..', 'logs', 'revelare_master.db'))
    
    # AI/ML Services
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    GOOGLE_SPEECH_API_KEY = os.environ.get('GOOGLE_SPEECH_API_KEY', '')
    AI_ASSISTANT_API_KEY = os.environ.get('AI_ASSISTANT_API_KEY', '')  # For AI-assisted analysis (OpenAI, Anthropic, Gemini, etc.)
    AI_ASSISTANT_PROVIDER = os.environ.get('AI_ASSISTANT_PROVIDER', 'openai')  # 'openai', 'anthropic', or 'gemini'
    
    # IP Geolocation & Threat Intelligence (IMPLEMENTED)
    IP_API_KEY = os.environ.get('IP_API_KEY', '')  # ip-api.com (free)
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')  # IP reputation
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')  # Malware/URL analysis
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')  # Device intelligence
    
    # Domain & URL Intelligence (IMPLEMENTED)
    URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY', '')  # URL analysis & screenshots
    
    # Blockchain & Cryptocurrency (IMPLEMENTED)
    BITCOIN_ABUSE_API_KEY = os.environ.get('BITCOIN_ABUSE_API_KEY', '')  # Bitcoin address reputation
    CHAINABUSE_API_KEY = os.environ.get('CHAINABUSE_API_KEY', '')  # Multi-chain abuse detection

    # Email Server Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    
    # API Rate Limits (requests per minute) - IMPLEMENTED APIs ONLY
    IP_API_RATE_LIMIT = float(os.environ.get('IP_API_RATE_LIMIT', '0.5'))  # ip-api.com (free tier)
    ABUSEIPDB_RATE_LIMIT = float(os.environ.get('ABUSEIPDB_RATE_LIMIT', '1.0'))  # 1000/day free
    VIRUSTOTAL_RATE_LIMIT = float(os.environ.get('VIRUSTOTAL_RATE_LIMIT', '4.0'))  # 500/hour free
    SHODAN_RATE_LIMIT = float(os.environ.get('SHODAN_RATE_LIMIT', '1.0'))  # 100/month free
    URLSCAN_RATE_LIMIT = float(os.environ.get('URLSCAN_RATE_LIMIT', '1.0'))  # 1000/month free
    BITCOIN_ABUSE_RATE_LIMIT = float(os.environ.get('BITCOIN_ABUSE_RATE_LIMIT', '1.0'))  # Free
    CHAINABUSE_RATE_LIMIT = float(os.environ.get('CHAINABUSE_RATE_LIMIT', '1.0'))  # Free
    
    # API Timeouts (seconds) - IMPLEMENTED APIs ONLY
    IP_API_TIMEOUT = int(os.environ.get('IP_API_TIMEOUT', '15'))
    ABUSEIPDB_TIMEOUT = int(os.environ.get('ABUSEIPDB_TIMEOUT', '10'))
    VIRUSTOTAL_TIMEOUT = int(os.environ.get('VIRUSTOTAL_TIMEOUT', '15'))
    SHODAN_TIMEOUT = int(os.environ.get('SHODAN_TIMEOUT', '10'))
    URLSCAN_TIMEOUT = int(os.environ.get('URLSCAN_TIMEOUT', '15'))
    BITCOIN_ABUSE_TIMEOUT = int(os.environ.get('BITCOIN_ABUSE_TIMEOUT', '10'))
    CHAINABUSE_TIMEOUT = int(os.environ.get('CHAINABUSE_TIMEOUT', '10'))

    LOG_LEVEL = os.environ.get('REVELARE_LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    REGEX_PATTERNS = {
        # --- Network Identifiers ---
        # IPv4 - catches IPs at start of lines and avoids version numbers
        'IPv4': r'(?:^|(?<=[^\w.]))((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:$|(?=[^\w.]))',
        # IPv4 with port - improved to avoid matching version numbers
        'IPv4_with_Port': r'(?:^|(?<=[^\w.]))((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):([1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])(?:$|(?=[^\w.]))',
        # IPv6 - comprehensive pattern
        'IPv6': r'\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b',
        # URLs - Added sftp, ftp, ws (websockets) support
        'URLs': r'\b(?:https?|sftp|ftp|ws)://(?!.*\.\.)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])?(?:/[^\s<>"\'{}|\\^`\[\]]*)?\b',
        # Onion addresses (Tor) - critical for dark web investigations
        'Onion_Addresses': r'\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b',
        # Email - hex-dump protection with proper format validation
        'Email_Addresses': r'(?<![a-fA-F0-9])(?<![a-zA-Z0-9._%+-])[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,61}[a-zA-Z0-9])?@(?!.*\.\.)(?!.*@)[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}(?![a-fA-F0-9])(?![a-zA-Z0-9._%+-])\b',
        
        # --- Financial Identifiers ---
        # Credit Cards - Split Visa/MC/Discover (16 digits) and Amex (15 digits) to reduce false positives
        'Credit_Card_VisaMcDiscover': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12})\b',
        'Credit_Card_Amex': r'\b3[47][0-9]{13}\b',
        # Legacy pattern for backward compatibility
        'Credit_Card_Numbers': r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47][0-9]{13}\b',
        
        # --- Cryptocurrency ---
        # Bitcoin - Added SegWit (bc1) support
        'Bitcoin_Addresses': r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b',
        # Ethereum
        'Ethereum_Addresses': r'\b0x[a-fA-F0-9]{40}\b(?![\da-fA-F])',
        # Monero - Critical for dark web investigations
        'Monero_Addresses': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        # IBAN - International Bank Account Number (crucial for wire fraud)
        'IBAN': r'\b[A-Z]{2}[0-9]{2}[a-zA-Z0-9]{4}[0-9]{7}([a-zA-Z0-9]?){0,16}\b',
        
        # --- Personal Identifiers ---
        'SSN': r'\b(?!000|666|9\d{2})([0-6]\d{2}|7[0-6]\d|77[0-2])[- ]?(?!00)([0-9]\d)[- ]?(?!0000)(\d{4})\b',
        # Phones - Expanded to catch E.164 (International) format
        'Phone_Numbers': r'\b(?:\+?1[-.\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b|\b\+\d{1,3}[-.\s]?\d{3,}[-.\s]?\d{3,}\b',
        
        # --- Timestamps ---
        'ISO_Timestamps': r'\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[T ](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)?\b',
        # Unix timestamps - Tightened to recent years (2020-2030) to avoid matching random integers
        'Unix_Timestamps_Recent': r'\b1(?:5[7-9]|6\d|7[0-5])\d{7}(?:\.\d{1,3})?\b',
        # Legacy pattern for backward compatibility
        'Unix_Timestamps': r'\b(?:1[0-3]\d{8}|[2-9]\d{9})(?:\.\d{1,3})?\b',
        
        # --- Device Identifiers ---
        'Device_IDs_UUIDs': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1345][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b',
        'MAC_Addresses': r'\b(?<![\da-fA-F])([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})(?![\da-fA-F])\b',
        'User_Agents': r'\bUser-Agent\s*:\s*[^\r\n]{20,}\b'
    }

    FILTER_PATTERNS = {
        'Common_Irrelevant_IPs': [
            r'^127\.0\.0\.1$',
            r'^0\.0\.0\.0$',
            r'^255\.255\.255\.255$',
            # Added loopback/link-local ranges often found in system logs
            r'^169\.254\.',
            r'^10\.',
            r'^192\.168\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'
        ],
        'Common_Irrelevant_Domains': [
            r'example\.com',
            r'w3\.org',
            r'schemas\.microsoft\.com',  # Common in XML/Office extractions
            r'googleapis\.com',           # Common in code extraction, rarely the fraud target
            r'gstatic\.com'
        ],
        'False_Positive_Emails': [
            r'example\.com',
            r'domain\.com',
            r'server\.com',
            r'test\.com',
            r'yourdomain\.com'
        ]
    }

    ALLOWED_EXTENSIONS = {
        'text': ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.md'],
        'email': ['.eml', '.msg', '.mbox'],
        'documents': ['.pdf', '.docx', '.xlsx', '.pptx'],
        'archives': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'data': ['.db', '.sqlite'],
        'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'],
        'audio': ['.mp3', '.wav', '.flac'],
        'video': ['.mp4', '.avi', '.mkv', '.mov']
    }

    @classmethod
    def validate_config(cls) -> List[str]:
        errors = []
        try:
            os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
            test_file = os.path.join(cls.UPLOAD_FOLDER, '.config_test')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
        except Exception as e:
            errors.append(f"Cannot create or write to upload folder '{cls.UPLOAD_FOLDER}': {e}")

        if not isinstance(cls.PORT, int) or not (1 <= cls.PORT <= 65535):
            errors.append(f"Invalid port number: {cls.PORT}")

        if cls.MAX_CONTENT_LENGTH is not None and (not isinstance(cls.MAX_CONTENT_LENGTH, int) or cls.MAX_CONTENT_LENGTH <= 0):
            errors.append(f"Invalid max content length: {cls.MAX_CONTENT_LENGTH}")

        for category, pattern in cls.REGEX_PATTERNS.items():
            try:
                import re
                re.compile(pattern)
            except re.error as e:
                errors.append(f"Invalid regex pattern for {category}: {e}")

        return errors