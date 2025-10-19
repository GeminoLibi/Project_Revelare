
````markdown
# Project Revelare - Documentation

This documentation covers Project Revelare v2.5, an advanced digital forensics and data extraction platform. It features a unified web and command-line interface, intelligent evidence processing, and comprehensive case management.

## 🚀 Quick Start

The recommended way to run the application is via the unified launcher.

```bash
# From the project root directory
python start.py
````

This will present an interactive menu with the following options:

  * **[1] Launch Web Interface**: Starts the Flask server and opens the GUI in your browser.
  * **[2] Launch Command Line Interface (CLI)**: Opens an interactive shell for direct commands.
  * **[3] Run Case Onboarding Wizard**: A guided setup for creating a new case.
  * **[4] Run String Search Tool**: A prompt-based tool for finding strings in a project.
  * **[5] Run Email Archive Analyzer**: A prompt-based tool for analyzing email archives.
  * **[6] Access Fractal Encryption Tool**: Instructions on how to use this feature via the web UI.

-----

## 🔧 Installation

### Prerequisites

  * Python 3.8+
  * **Tesseract OCR Engine** (for image-to-text functionality)
      * **Windows**: Download from [Tesseract at UB Mannheim](https://github.com/UB-Mannheim/tesseract/wiki)
      * **macOS**: `brew install tesseract`
      * **Linux**: `sudo apt install tesseract-ocr`

### Installation Steps

1.  Navigate to the project's root directory.
2.  Install all required Python packages using the `requirements.txt` file:

<!-- end list -->

```bash
pip install -r requirements.txt
```

3.  Verify the installation by running the launcher:

<!-- end list -->

```bash
python start.py
```

-----

## 📁 Final Project Structure

```
/project_revelare/
├── cases/
│   └── (Generated automatically for case data)
├── logs/
│   └── (Generated automatically for logs and database)
├── revelare/
│   ├── cli/
│   │   ├── revelare_cli.py
│   │   └── suite.py
│   ├── config/
│   │   └── config.py
│   ├── core/
│   │   ├── case_manager.py
│   │   ├── data_enhancer.py
│   │   ├── enrichers.py
│   │   ├── extractor.py
│   │   ├── file_processors.py
│   │   └── validators.py
│   ├── utils/
│   │   ├── file_extractor.py
│   │   ├── fractal_encryption.py
│   │   ├── geoip_service.py
│   │   ├── logger.py
│   │   ├── mbox_viewer.py
│   │   ├── reporter.py
│   │   ├── revelare_onboard.py
│   │   ├── security.py
│   │   └── string_search.py
│   └── web/
│       ├── static/
│       │   ├── css/
│       │   │   └── style.css
│       │   └── js/
│       │       ├── main.js
│       │       └── report.js
│       └── templates/
│           ├── (all .html files)
├── launch_gui.py
├── launch_web.py
├── requirements.txt
├── shutdown_server.py
├── start.py
└── README.md
```

-----

## 🔍 Features

### Core Capabilities

  * **Unified Interface**: Access all features through a clean web UI or a powerful command-line interface, launched from a single `start.py` script.
  * **Case Management**: Create, manage, and add evidence to structured case folders.
  * **Automated Processing**: Evidence files are processed in the background, keeping the UI responsive.
  * **Multi-Format Support**: Handles over 50 file types, including automatic extraction of ZIP, RAR, and 7Z archives.
  * **Advanced IOC Extraction**: Extracts 20+ indicator types (IPs, emails, URLs, metadata, financial data, etc.) using regex patterns defined in `config.py`.
  * **OCR & Transcription**: Extracts text from images and PDFs using Tesseract and transcribes audio from media files using Whisper.

### Forensic Tools

  * **Link Analysis (Enhanced)**: Visually graphs connections between cases. Automatically discovers not only direct links but also "second-degree" connections (related cases that share other indicators).
  * **String Search (Enhanced)**: An advanced tool to find specific text within all files of a project, now with support for both literal strings and **Regular Expressions**.
  * **Email Browser**: A dedicated interface to parse, view, and analyze email archives (MBOX, EML, PST) found within cases.
  * **Fractal Encryption**: A unique steganography tool to encrypt and hide files within the structure of a fractal image.

### Reporting & Security

  * **Multi-Page Reports**: Generates comprehensive, interactive HTML reports with filterable tables for indicators, files, geolocation, security intelligence, and technical analysis.
  * **Security Intelligence**: Advanced threat analysis with 20+ threat types including suspicious IPs, malware URLs, data exposure indicators, and more with severity levels and confidence scoring.
  * **Enhanced IP Geolocation**: Improved IP enrichment with proper handling of IP:port combinations, MaxMind GeoLite2 integration, and comprehensive location data.
  * **Portable Report Generation**: Create self-contained report packages with embedded reader application for easy distribution to law enforcement and stakeholders.
  * **API Integration**: Support for 25+ external APIs including AbuseIPDB, VirusTotal, Chainabuse, Shodan, GreyNoise, and more for enhanced threat intelligence.
  * **Advanced Filtering & Sorting**: Interactive filtering and sorting on all report pages with real-time search capabilities.
  * **Secure by Design**: Includes robust input validation, path traversal protection, secure file handling, and prevention against common web vulnerabilities.

<!-- end list -->

````
# Project Revelare v2.5

**Advanced Digital Forensics and Incident Response Platform**

A comprehensive forensic analysis tool designed to extract, analyze, and report on digital evidence from multiple file formats. Features intelligent processing with time estimation, advanced pattern recognition, unified case management, and real-time processing. Built for law enforcement, incident response teams, and digital forensics professionals.

## 🚀 Key Features

### Core Capabilities
- **Intelligent Archive Processing**: Smart batching with time estimation and user warnings for large data sets
- **Multi-Format Support**: Process 50+ file types including TXT, PDF, DOCX, XLSX, JSON, CSV, ZIP, EML, MSG, Images, Audio, Video, and more
- **OCR & Transcription**: Extract text from images (OCR) and audio/video files (speech-to-text)
- **Advanced IOC Extraction**: Identify 20+ types of indicators including IPs, emails, URLs, file paths, credit cards, routing numbers, and more
- **Enhanced Pattern Recognition**: Structured data detection (Account Number: XXXXXX, First Name: John, etc.)
- **Unified Case Management**: Create cases, add files, browse directories across CLI and web interfaces
- **Real-time Processing**: Live progress monitoring and status updates with polling
- **Comprehensive Reporting**: Generate detailed HTML reports with enriched data and media analysis
- **File Accumulation**: Select and accumulate multiple file batches before processing

### Supported File Types
- **Documents**: PDF (with OCR), DOCX, XLSX, PPTX, RTF, TXT
- **Archives**: ZIP, RAR, 7Z, TAR, GZ (recursive extraction)
- **Email**: EML, MSG, PST, MBOX
- **Data**: JSON, CSV, XML, LOG
- **Images**: JPG, PNG, GIF, BMP, TIFF, WebP (OCR processing)
- **Audio**: MP3, WAV, FLAC, AAC, OGG, WMA, M4A, AIFF (speech-to-text)
- **Video**: MP4, AVI, MKV, MOV, WMV, FLV (audio extraction + transcription)
- **System**: Executables, Scripts, Config files

### Forensic Indicators
- **Personal Data**: Email addresses, phone numbers, SSN patterns, names (structured detection)
- **Financial Data**: Credit card numbers (16-digit with formatting), bank account numbers, routing numbers (verified against bank database)
- **Medical Data**: Medical record numbers (rejects all zeros), prescription numbers, insurance policy numbers
- **Technical Data**: IP addresses (IPv4/IPv6), URLs/domains, device IDs/UUIDs, file paths, timestamps
- **Security Data**: User agents, tokens, API keys, session IDs, process names, connection info
- **Government/Legal**: Case numbers, incident reports, badge numbers, passport numbers, driver's licenses
- **Location Data**: GPS coordinates, street addresses, zip codes
- **Digital Assets**: Bitcoin/Ethereum addresses, private keys, wallet addresses

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (recommended)
- 4GB+ RAM
- 1GB+ free disk space

### Quick Start
```bash
# Clone the repository
git clone https://github.com/GeminoLibi/Project_Revelare.git
cd project-revelare

# Install dependencies
pip install -r requirements.txt

# For OCR functionality (optional)
pip install pytesseract opencv-python

# For transcription functionality (optional)
pip install openai-whisper speechrecognition pydub

# Launch the unified interface (EASIEST WAY)
python start.py

# Or use the Windows batch file launcher
launch.bat  # Windows only - includes dependency checks

# This will show you options for:
# - Web Interface (recommended for most users)
# - Command Line Interface (advanced users)
# - Quick Start Wizard (first-time setup)
# - String Search Tool
# - MBOX File Analyzer
```

### Alternative Launch Methods
```bash
# Direct CLI processing (bypasses unified launcher)
python -m revelare.cli.revelare_cli -p "case_name" -f "evidence1.zip"

# Web interface only (bypasses unified launcher)
python -m revelare.cli.suite

# Individual tools
python -m revelare.utils.string_search
python -m revelare.cli.fractal_cli
```

## 📖 Usage

### Interactive Onboarding
```bash
# Launch unified interface and choose option 3
python start.py
# Then select: [3] QUICK START (Interactive Onboarding)
```
This launches an interactive wizard that:
- Collects case metadata (investigator, agency, case info)
- Creates organized project structure
- Guides evidence file placement
- Generates processing scripts

### Direct Processing
```bash
# Launch unified interface and choose option 2
python start.py
# Then select: [2] COMMAND LINE INTERFACE (CLI)
# Enter commands at the CLI> prompt:
#   --onboard                    # Interactive case onboarding
#   -p "case_001" -f evidence.zip    # Process files
#   --add-files "case_001" --files new.zip  # Add to existing case

# Or use direct CLI commands:
python -m revelare.cli.revelare_cli -p "case_001" -f evidence.zip
python -m revelare.cli.revelare_cli --onboard
python -m revelare.cli.revelare_cli --add-files "existing_case" --files new_evidence.zip
```

### Web Interface
```bash
python start.py
# Choose option 1: Web Interface
```
Access the web interface at `http://localhost:5000` for:
- **Case Creation**: Interactive onboarding with metadata collection
- **File Upload**: Accumulative file selection (add multiple batches)
- **Intelligent Processing**: Time estimation and warnings for large archives
- **Evidence Processing**: Real-time status updates and progress monitoring
- **Directory Browsing**: Interactive file explorer with search
- **Add Files**: Upload additional evidence to existing cases
- **Email Browser**: Analyze email archives (MBOX, Maildir, EML, PST) with automatic detection
- **Case Management**: Re-analyze evidence, add notes, browse case files
- **Fractal Encryption**: Encrypt files into fractal images using advanced steganography
- **Report Viewing**: Comprehensive HTML reports with enriched data
- **Export Options**: JSON, CSV, and warrant formats

## 📁 Project Structure

```
project_revelare/
├── revelare/                       # Core package
│   ├── core/                       # Core processing modules
│   │   ├── case_manager.py         # Unified case management
│   │   ├── extractor.py            # IOC extraction engine
│   │   ├── file_processors.py      # File type handlers (with OCR/transcription)
│   │   └── validators.py           # Data validation
│   ├── cli/                        # Command line interfaces
│   │   ├── revelare_cli.py         # Main CLI
│   │   └── suite.py                # Web application
│   ├── utils/                      # Utility modules
│   │   ├── data_enhancer.py        # IOC enrichment
│   │   ├── exporter.py             # Portable report generation
│   │   ├── file_extractor.py       # Archive handling
│   │   ├── geoip_service.py        # IP geolocation & enrichment
│   │   ├── logger.py               # Logging system
│   │   ├── mbox_viewer.py          # Email browser module
│   │   ├── reporter.py             # Report generation
│   │   ├── security.py             # Security validation
│   │   ├── string_search.py        # Pattern matching
│   │   └── revelare_onboard.py     # Case onboarding
│   ├── web/                        # Web interface files
│   │   ├── templates/              # HTML templates
│   │   └── static/                 # CSS/JS/images
│   │       ├── css/
│   │       │   └── style.css       # Enhanced styling with API sections
│   │       └── js/
│   │           ├── main.js         # Main JavaScript functionality
│   │           └── report.js       # Interactive report tables with filtering
│   └── config/
│       └── config.py               # Configuration with API integration
├── cases/                          # Case directories
│   └── [case_name]/
│       ├── case_metadata.json      # Case information
│       ├── evidence/               # Original evidence files
│       ├── extracted_files/        # Archive extractions
│       ├── reports/                # Generated reports
│       ├── analysis/               # Processing artifacts
│       └── logs/                   # Case-specific logs
├── logs/                           # Application logs & database
│   ├── revelare_master.db          # Master indicator database
│   ├── revelare.log                # Application logs
│   └── revelare_audit.log          # Security audit logs
├── start.py                        # Unified launcher
├── requirements.txt                # Dependencies
└── README.md                       # This file
```

## 🤖 OCR & Transcription Setup

### OCR (Optical Character Recognition)
Extract text from images embedded in PDFs or standalone image files.

**Installation:**
```bash
# Install OCR dependencies
pip install pytesseract opencv-python

# Install Tesseract OCR engine (required)
# Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki
# Linux: sudo apt install tesseract-ocr
# macOS: brew install tesseract
```

**Supported Image Formats:**
- JPG, JPEG, PNG, GIF, BMP, TIFF, TIF, WebP
- Automatic preprocessing for better accuracy
- Fallback to OpenCV when PIL fails

### Speech-to-Text Transcription
Extract spoken content from audio and video files.

**Installation:**
```bash
# Install transcription dependencies
pip install openai-whisper speechrecognition pydub

# Optional: Install FFmpeg for audio processing
# Windows: Download from https://ffmpeg.org/download.html
# Linux: sudo apt install ffmpeg
# macOS: brew install ffmpeg
```

**Supported Audio/Video Formats:**
- **Audio**: MP3, WAV, FLAC, AAC, OGG, WMA, M4A, AIFF
- **Video**: MP4, AVI, MKV, MOV, WMV, FLV (audio extracted automatically)
- **Engines**: OpenAI Whisper (primary), Google Speech Recognition (fallback)

### Fractal Encryption & Steganography
Hide files within fractal images using Iterated Function Systems (IFS).

**Features:**
- Encrypt any file into fractal patterns
- Visual steganography (data hidden in image structure)
- Custom IFS keys for encryption strength
- Real-time fractal visualization
- Export as JSON or PNG images

**How it Works:**
1. File data is converted to binary stream
2. Data bits encoded into fractal point coordinates and RGB colors
3. IFS transforms used as encryption keys
4. Result rendered as beautiful fractal images
5. Original file recovered by reverse transformation

### Configuration
```python
# In config.py - OCR/Transcription settings
OCR_ENABLED = True                    # Enable/disable OCR
WHISPER_MODEL = "base"               # Whisper model size (tiny, base, small, medium, large)
TRANSCRIPTION_ENABLED = True         # Enable/disable transcription
AUTO_EXTRACT_AUDIO = True            # Extract audio from video files
```

## 🔌 API Integration & Threat Intelligence

### Supported APIs
Project Revelare v2.6 includes comprehensive API integration for enhanced threat intelligence and data enrichment:

#### IP Geolocation & Threat Intelligence
- **MaxMind GeoLite2**: Local IP geolocation database (included)
- **IP-API**: Free IP geolocation service
- **AbuseIPDB**: IP reputation and abuse reporting
- **VirusTotal**: Malware and URL analysis
- **Shodan**: Internet-connected device search
- **GreyNoise**: Internet background noise analysis
- **CrowdStrike**: Enterprise threat intelligence

#### Domain & URL Intelligence
- **Whois API**: Domain registration information
- **URLScan**: URL analysis and screenshots
- **PhishTank**: Phishing URL database

#### Email & Communication Intelligence
- **Hunter.io**: Email verification and finder
- **Clearbit**: Company and person data

#### Blockchain & Cryptocurrency
- **Etherscan**: Ethereum blockchain analysis
- **Bitcoin Abuse**: Bitcoin address reputation
- **Chainabuse**: Multi-chain cryptocurrency abuse detection
- **Coinbase**: Cryptocurrency exchange data

#### Malware & File Analysis
- **Malware Bazaar**: Malware sample database
- **Any.run**: Dynamic malware analysis
- **Hybrid Analysis**: Malware sandbox

#### Network & Infrastructure
- **Censys**: Internet-wide scanning data
- **BinaryEdge**: Attack surface monitoring
- **SecurityTrails**: DNS and domain intelligence

### API Configuration
```bash
# Create .env file in project root
cp env.template .env

# Edit .env file with your API keys
# Example:
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
CHAINABUSE_API_KEY=your_key_here
# ... add other API keys as needed
```

### Rate Limiting & Timeouts
All APIs include configurable rate limiting and timeout settings:
```python
# Rate limits (requests per minute)
ABUSEIPDB_RATE_LIMIT = 1.0
VIRUSTOTAL_RATE_LIMIT = 4.0
SHODAN_RATE_LIMIT = 1.0

# Timeouts (seconds)
ABUSEIPDB_TIMEOUT = 10
VIRUSTOTAL_TIMEOUT = 15
SHODAN_TIMEOUT = 10
```


## 🔧 Configuration

### Intelligent Processing Settings
```python
# Archive processing - Intelligent chunking instead of hard limits
ARCHIVE_BATCH_SIZE = 100          # Process files in batches
LARGE_ARCHIVE_THRESHOLD = 500     # Consider archive "large" if >500 files
HUGE_ARCHIVE_THRESHOLD = 2000     # Consider archive "huge" if >2000 files
MAX_FILE_SIZE_IN_ARCHIVE = 500MB  # Max per file in archive

# Processing time estimates (seconds per MB by file type)
PROCESSING_RATES = {
    'text': 0.01,     # Very fast
    'binary': 0.05,   # Medium
    'archive': 2.0,   # Slow (nested)
    'image': 0.1,     # OCR processing
    'pdf': 0.2,       # Text extraction
}
```

### File Size Limits
- Default max file size: 100MB (individual files)
- Archive max file size: 500MB (files within archives)
- Override with `--max-size` parameter
- Large files processed in 64KB chunks with overlap

### Processing Options
- `--verbose`: Enable detailed logging
- `--debug`: Enable debug mode with full tracebacks
- `--output`: Specify output directory
- `--project`: Set project/case name
- `--add-files`: Add files to existing case (specify case name)
- `--recursive`: Enable recursive archive extraction

### Case Management
- **Unified Interface**: CLI and web interface use the same case management system
- **Onboarding Required**: All cases start with mandatory metadata collection
- **Intelligent Processing**: Time estimation and warnings for large data sets
- **File Accumulation**: Web interface allows accumulating files across multiple selections
- **Real-time Updates**: Live status monitoring with automatic refresh
- **Directory Browsing**: Interactive file explorer with search capabilities
- **Add Files Later**: Upload additional evidence to existing cases anytime
- **Email Archive Detection**: Automatically finds and lists email archives in cases

## 📊 Output

### Generated Files
- **indicators.json**: Raw extracted indicators
- **indicators.csv**: Tabular format for analysis
- **report.html**: Comprehensive forensic report
- **raw_findings.json**: Complete analysis results

### Report Contents
- Executive summary
- Indicator counts by type
- Enriched IP address data with geolocation
- Security intelligence with threat analysis
- File processing statistics
- Timeline analysis
- Exportable data tables
- Interactive filtering and sorting

### Portable Report Generation
Generate self-contained report packages for easy distribution:

```bash
# After processing a case, the system automatically generates:
# - Portable report package (ZIP file)
# - Embedded reader application
# - Auto-opening browser functionality
# - Standalone operation (no server required)
```

**Portable Report Features:**
- **Self-contained**: Includes all data and reader application
- **Easy Distribution**: Single ZIP file contains everything needed
- **Auto-opening**: Automatically opens in browser when launched
- **Standalone**: No server installation required on recipient's machine
- **Interactive**: Full filtering, sorting, and search capabilities
- **Professional**: Clean interface suitable for law enforcement and stakeholders

## 🚨 Security Features

- Path traversal protection
- File type validation
- Size limit enforcement
- Safe file extraction
- Input sanitization
- Secure temporary file handling

## 📈 Performance

- Multi-threaded processing
- Chunked file handling
- Memory-efficient extraction
- Progress monitoring
- Performance metrics logging

## 🐛 Troubleshooting

### Common Issues
1. **File too large**: Use `--max-size` to increase limits
2. **Permission errors**: Run as administrator
3. **Memory issues**: Process files individually
4. **Path errors**: Use absolute paths for files

### Logs
- Main log: `revelare.log`
- Audit log: `revelare_audit.log`
- Case logs: `cases/[case_name]/logs/`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support, issues, or feature requests:
- GitHub Repository: https://github.com/GeminoLibi/Project_Revelare
- Create an issue on GitHub
- Check the troubleshooting section

## 🔄 Version History

- **v2.6**: Enhanced security intelligence, improved IP geolocation, portable report generation, comprehensive API integration, advanced filtering and sorting
  - **Security Intelligence**: Comprehensive threat analysis with 20+ threat types, severity levels, and confidence scoring
  - **Enhanced IP Geolocation**: Improved IP enrichment with proper handling of IP:port combinations, MaxMind GeoLite2 integration
  - **Portable Reports**: Generate self-contained report packages with embedded reader application for easy distribution
  - **API Integration**: Support for 25+ external APIs including AbuseIPDB, VirusTotal, Chainabuse, Shodan, and more
  - **Advanced Filtering**: Interactive filtering and sorting on all report pages with real-time search
  - **Settings Management**: Centralized API key management with .env file support and rate limiting configuration
  - **Improved Data Processing**: Enhanced geographic data synthesis ensuring every IP gets location data where available
- **v2.5**: Intelligent archive processing with time estimation, enhanced pattern recognition (routing numbers, structured data), email browser (replaces MBOX viewer), medical record validation, webmail removal, improved large file chunking
- **v2.4**: OCR & transcription, unified case management, file accumulation, real-time status updates, directory browsing, fractal encryption & steganography
- **v2.3**: Enhanced processing, improved error handling, real-time monitoring
- **v2.2**: Added web interface, improved reporting
- **v2.1**: Enhanced extraction capabilities
- **v2.0**: Complete rewrite with new architecture


