# Project Revelare - Documentation

This documentation covers Project Revelare v2.5, an advanced digital forensics and incident response platform with intelligent processing, multi-format evidence analysis, and comprehensive case management.

## 🚀 Quick Start

### Unified Launcher (Recommended)
```bash
# From the project root directory
python start.py

# Interactive menu options:
# [1] WEB INTERFACE      - Browser-based GUI with real-time processing
# [2] COMMAND LINE       - Direct CLI with interactive command entry
# [3] QUICK START        - Interactive onboarding wizard
# [4] STRING SEARCH      - Pattern matching and text analysis
# [5] EMAIL BROWSER      - Email archive analysis (MBOX, Maildir, EML, PST)
# [6] FRACTAL ENCRYPTION - Advanced steganography tool
```

### Direct Module Usage
```bash
# Web interface
python -m revelare.cli.suite

# CLI processing
python -m revelare.cli.revelare_cli --onboard

# Individual tools
python -m revelare.utils.string_search
python -m revelare.cli.fractal_cli
```

## 📁 Project Structure

```
project_revelare/
├── revelare/                       # Core Python package
│   ├── core/                       # Core processing modules
│   │   ├── case_manager.py         # Unified case management
│   │   ├── extractor.py            # IOC extraction engine (20+ patterns)
│   │   ├── file_processors.py      # File type handlers (OCR/transcription)
│   │   └── validators.py           # Data validation & enrichment
│   ├── cli/                        # Command-line interfaces
│   │   ├── suite.py                # Flask web application
│   │   ├── revelare_cli.py         # Direct CLI processing
│   │   └── fractal_cli.py          # Fractal encryption CLI
│   ├── utils/                      # Utility modules
│   │   ├── data_enhancer.py        # IOC enrichment & metadata
│   │   ├── file_extractor.py       # Archive handling & extraction
│   │   ├── geoip_service.py        # IP geolocation service
│   │   ├── logger.py               # Centralized logging system
│   │   ├── reporter.py             # Report generation (HTML/CSV/JSON)
│   │   ├── security.py             # Security validation & sanitization
│   │   ├── string_search.py        # Advanced pattern matching
│   │   ├── revelare_onboard.py     # Interactive case onboarding
│   │   └── email_browser.py        # Multi-format email analysis
│   └── web/                        # Web interface files
│       ├── templates/              # Jinja2 HTML templates
│       └── static/                 # CSS, JS, images
├── cases/                          # Case data directory
├── logs/                           # Application logs & database
├── start.py                        # Unified launcher (recommended)
├── requirements.txt                # Python dependencies
├── README.md                       # Main project documentation
└── docs/                           # Additional documentation (this file)
```

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- 4GB+ RAM recommended
- 1GB+ free disk space

### Basic Installation
```bash
# Clone or download the project
cd project_revelare/

# Install core dependencies
pip install -r requirements.txt
```

### Optional Dependencies (Enhanced Features)
```bash
# OCR functionality (image text extraction)
pip install pytesseract opencv-python Pillow

# Audio/Video transcription (speech-to-text)
pip install openai-whisper speechrecognition pydub

# Install Tesseract OCR engine (for OCR)
# Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki
# Linux: sudo apt install tesseract-ocr
# macOS: brew install tesseract
```

### Verification
```bash
# Test the installation
python start.py

# Should display the unified launcher menu
# Select [Q] to quit if working correctly
```

## 📖 Usage Examples

### Web Interface (Recommended)
```bash
# Launch unified interface
python start.py
# Select option [1] WEB INTERFACE

# Direct web interface launch
python -m revelare.cli.suite
# Opens at http://localhost:5000

# Features:
# - Case creation with onboarding
# - File upload with intelligent processing
# - Real-time progress monitoring
# - Case management and file browsing
# - Email browser for archives
# - Report viewing and export
```

### Command Line Interface
```bash
# Launch unified interface
python start.py
# Select option [2] COMMAND LINE INTERFACE
# Enter commands at CLI> prompt:
#   --onboard                    # Interactive case setup
#   -p "case_001" -f evidence.zip    # Process files
#   --add-files "case_001" --files new.zip  # Add to existing case

# Direct CLI usage
python -m revelare.cli.revelare_cli --onboard
python -m revelare.cli.revelare_cli -p "case_001" -f evidence.zip
```

### Interactive Onboarding
```bash
# Via unified launcher (recommended)
python start.py
# Select option [3] QUICK START

# Direct onboarding
python -m revelare.cli.revelare_cli --onboard
# Guides through: investigator info, agency details, case metadata, evidence collection
```

### Email Browser
```bash
# Via unified launcher
python start.py
# Select option [5] EMAIL BROWSER

# Direct usage
python -m revelare.utils.email_browser
# Supports: MBOX, Maildir, EML, PST formats
# Automatic archive detection and processing
```

### String Search Tool
```bash
# Via unified launcher
python start.py
# Select option [4] STRING SEARCH TOOL

# Direct usage
python -m revelare.utils.string_search /path/to/search -s "password" "secret" -o results.csv
python -m revelare.utils.string_search /path/to/search -s "api_key" -e .txt .log .json
```

### Fractal Encryption
```bash
# Via unified launcher
python start.py
# Select option [6] FRACTAL ENCRYPTION TOOL

# Direct usage
python -m revelare.cli.fractal_cli encrypt file.txt
python -m revelare.cli.fractal_cli decrypt file.fractal.json
```

## ⚙️ Configuration

Configuration is managed through `revelare/config/config.py`. Key settings:

### Core Settings
- **UPLOAD_FOLDER**: Case data storage (default: `cases/`)
- **DATABASE**: SQLite database location (default: `logs/revelare_master.db`)
- **MAX_CONTENT_LENGTH**: Maximum upload size (default: 2GB)
- **HOST/PORT**: Web interface (default: localhost:5000)

### Intelligent Processing
- **ARCHIVE_BATCH_SIZE**: Files processed per batch (default: 100)
- **LARGE_ARCHIVE_THRESHOLD**: Consider archive "large" if >500 files
- **HUGE_ARCHIVE_THRESHOLD**: Consider archive "huge" if >2000 files
- **MAX_FILE_SIZE_IN_ARCHIVE**: Max individual file size in archives (500MB)

### Security & Validation
- **ALLOWED_EXTENSIONS**: Supported file types
- **REGEX_PATTERNS**: 20+ indicator extraction patterns
- **ROUTING_NUMBERS**: Bank routing number database for validation
- **IRRELEVANT_PATTERNS**: Patterns to filter out false positives

### OCR & Transcription
- **OCR_ENABLED**: Enable/disable image text extraction
- **WHISPER_MODEL**: Speech-to-text model (tiny, base, small, medium, large)
- **TRANSCRIPTION_ENABLED**: Enable/disable audio/video processing

## 🔍 Features

### Core Capabilities
- **Intelligent Archive Processing**: Smart batching with time estimation and user warnings
- **Multi-Format Support**: 50+ file types including ZIP, RAR, 7Z, PDF, DOCX, XLSX, JSON, CSV, XML, MBOX, EML, PST, images, audio, video
- **Advanced IOC Extraction**: 20+ indicator types with structured data detection
- **OCR & Transcription**: Extract text from images/PDFs, speech-to-text from audio/video
- **Unified Case Management**: Create, browse, and manage cases across CLI/web interfaces

### Forensic Indicators
- **Personal Data**: Email addresses, phone numbers, SSN patterns, names (structured detection)
- **Financial Data**: Credit card numbers (16-digit with formatting), bank account numbers, routing numbers (verified)
- **Medical Data**: Medical record numbers (rejects all zeros), prescription numbers, insurance policy numbers
- **Technical Data**: IP addresses (IPv4/IPv6), URLs/domains, device IDs, file paths, timestamps
- **Security Data**: User agents, tokens, API keys, session IDs, process names
- **Government/Legal**: Case numbers, incident reports, badge numbers, passport numbers
- **Location Data**: GPS coordinates, street addresses, zip codes
- **Digital Assets**: Bitcoin/Ethereum addresses, private keys, wallet addresses

### Advanced Processing
- **Email Browser**: Multi-format email analysis (MBOX, Maildir, EML, PST) with automatic detection
- **Fractal Encryption**: Hide files within fractal images using advanced steganography
- **String Search**: Advanced pattern matching with context and file type filtering
- **Report Generation**: Interactive HTML reports with filtering, sorting, and CSV export
- **Real-time Processing**: Live status updates and progress monitoring

### Security & Validation
- **Input Sanitization**: Path traversal protection and secure filename handling
- **File Type Validation**: Extension checking and content validation
- **Size Limits**: Configurable upload and processing limits
- **GeoIP Enrichment**: IP address geolocation and metadata enhancement

## 🛠️ Development

### Adding New Indicators
1. Add regex patterns to `revelare/config/config.py` REGEX_PATTERNS
2. Update EXTRACTION_CATEGORIES if needed
3. Add validation logic to `revelare/core/validators.py`
4. Test extraction with `revelare/core/extractor.py`

### Adding New File Processors
1. Extend `revelare/core/file_processors.py` with new processor class
2. Add file type detection in the main processing logic
3. Update ALLOWED_EXTENSIONS in `revelare/config/config.py`
4. Add any required dependencies to `requirements.txt`

### Adding New Report Features
1. Extend `revelare/utils/reporter.py` ReportGenerator class
2. Add export routes in `revelare/cli/suite.py`
3. Update web templates in `revelare/web/templates/`
4. Add JavaScript for interactive features

### Adding New CLI Tools
1. Create new module in `revelare/cli/` or `revelare/utils/`
2. Add entry to `start.py` launcher menu
3. Update main `README.md` documentation

## 📝 Logging

Logs are written to `logs/` directory:
- `logs/revelare.log` - Main application log with performance metrics
- `logs/revelare_audit.log` - Security audit log for all operations
- `logs/revelare_master.db` - SQLite database for case and indicator data

### Log Levels
- **DEBUG**: Detailed processing information (use with --debug flag)
- **INFO**: General operation status (default)
- **WARNING**: Non-critical issues
- **ERROR**: Processing failures
- **CRITICAL**: Security violations and system errors

## 🔒 Security

### Core Security Features
- **Input Validation**: Comprehensive sanitization and type checking
- **Path Traversal Protection**: Secure file path handling with base directory validation
- **File Type Restrictions**: Extension and content validation for uploads
- **Size Limits**: Configurable upload and processing limits with intelligent chunking
- **Secure Filename Handling**: Automatic sanitization of uploaded filenames

### Advanced Security
- **SQL Injection Prevention**: Parameterized queries in all database operations
- **XSS Protection**: Input sanitization for web interface
- **CSRF Protection**: Token-based request validation
- **Rate Limiting**: Built-in request throttling for web endpoints
- **Audit Logging**: Complete audit trail of all operations

### Encryption & Privacy
- **Fractal Encryption**: Advanced steganography for sensitive data protection
- **Database Encryption**: Optional SQLite encryption for stored case data
- **Secure Temporary Files**: Automatic cleanup of processing artifacts

## 📞 Support & Troubleshooting

### Getting Help
1. **Check Logs**: Review `logs/revelare.log` and `logs/revelare_audit.log`
2. **Configuration**: Verify settings in `revelare/config/config.py`
3. **Dependencies**: Ensure all optional dependencies are installed
4. **GitHub Issues**: Report bugs at https://github.com/GeminoLibi/Project_Revelare

### Common Issues
- **Import Errors**: Run `pip install -r requirements.txt`
- **OCR Issues**: Install Tesseract OCR engine and `pip install pytesseract`
- **Memory Issues**: Reduce batch sizes in config or process smaller files
- **Permission Errors**: Run as administrator or check file permissions

### Performance Tuning
- **Large Archives**: Adjust `ARCHIVE_BATCH_SIZE` in config
- **OCR Processing**: Use smaller Whisper models for faster transcription
- **Database Queries**: Enable indexes for large case databases
