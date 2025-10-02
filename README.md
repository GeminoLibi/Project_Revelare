# Project Revelare v1.0

**Advanced Digital Forensics and Incident Response Platform**

Project Revelare is a comprehensive digital forensics and incident response platform designed to extract, analyze, and visualize indicators of compromise (IOCs) from various file types. It provides both a modern web interface and command-line tools for digital forensics professionals, incident responders, and security analysts.

## 🚀 Key Features

### Core Capabilities
- **Multi-Format Support**: Process 40+ file types including TXT, PDF, DOCX, XLSX, JSON, CSV, ZIP, EML, MSG, and more
- **Advanced IOC Extraction**: Identify 15+ types of indicators, including IPs, emails, URLs, file paths, and more
- **Intelligent Filtering**: Remove irrelevant data and false positives automatically
- **Real-time Analysis**: Process files with live progress tracking and heartbeat monitoring
- **Interactive Reports**: Generate comprehensive HTML reports with visualizations
- **Legal Compliance**: Export data in formats suitable for legal warrants
- **Nested ZIP Processing**: Handle complex archive structures with depth limits

### Security & Performance
- **Security-First Design**: Protection against path traversal, XSS, SQL injection, and other attacks
- **Performance Optimized**: Pre-compiled regex patterns and chunked file processing
- **Comprehensive Logging**: Detailed audit trails for compliance and debugging
- **Error Handling**: Robust error recovery and graceful failure handling
- **Progress Monitoring**: Real-time updates every 5 files and 10 seconds

### User Experience
- **Modern Web Interface**: Responsive design with drag-and-drop file upload
- **Command-Line Tools**: Powerful CLI for automation and scripting
- **Complete CLI Maestro**: One-stop onboarding and processing solution
- **Link Analysis**: Advanced correlation and relationship mapping
- **Export Options**: JSON, CSV, and Legal Warrant formats

## 📋 Supported Indicator Types

| Category | Description | Examples |
|----------|-------------|----------|
| **IPv4/IPv6** | IP addresses with classification | 192.168.1.1, 2001:db8::1 |
| **Email Addresses** | Email addresses and domains | user@example.com |
| **URLs** | Web URLs and domains | https://malicious-site.com |
| **File Paths** | File system paths | C:\Windows\System32\malware.exe |
| **Credit Cards** | Credit card numbers | 4111-1111-1111-1111 |
| **Phone Numbers** | Phone numbers in various formats | (555) 123-4567 |
| **MAC Addresses** | Network interface addresses | 00:1B:44:11:3A:B7 |
| **User Agents** | Browser and application identifiers | Mozilla/5.0... |
| **Session IDs** | Session identifiers and tokens | abc123def456 |
| **Cookies** | HTTP cookies and values | session_token=xyz789 |
| **Registry Keys** | Windows registry entries | HKEY_LOCAL_MACHINE\SOFTWARE |
| **Process Names** | Executable names and processes | malware.exe, notepad.exe |
| **DNS Queries** | Domain name system queries | malicious-domain.com |
| **Network Protocols** | Network protocol identifiers | TCP, UDP, HTTP, HTTPS |

## 📁 Supported File Formats

### 📧 Email Formats
- **`.eml`** - Standard email message format (RFC 822) - **FULLY SUPPORTED**
- **`.msg`** - Microsoft Outlook message format (requires pywin32)
- **`.mbox`** - Unix mailbox format
- **`.mbx`** - Alternative mailbox format
- **`.pst`** - Outlook Personal Storage Table (binary scan)
- **`.ost`** - Outlook Offline Storage Table (binary scan)
- **`.dbx`** - Outlook Express mailbox (binary scan)
- **`.tbb`** - Thunderbird mailbox (binary scan)

### 📄 Document Formats
- **`.pdf`** - Portable Document Format (requires PyPDF2)
- **`.docx`** - Microsoft Word document (requires python-docx)
- **`.doc`** - Legacy Word document (requires python-docx)
- **`.xlsx`** - Microsoft Excel spreadsheet (requires pandas)
- **`.xls`** - Legacy Excel spreadsheet (requires pandas)
- **`.pptx`** - Microsoft PowerPoint presentation (requires python-docx)
- **`.ppt`** - Legacy PowerPoint presentation (requires python-docx)
- **`.odt`** - OpenDocument Text (binary scan)
- **`.ods`** - OpenDocument Spreadsheet (binary scan)
- **`.odp`** - OpenDocument Presentation (binary scan)

### 📁 Archive Formats
- **`.zip`** - ZIP archive (full support with nested processing)
- **`.rar`** - RAR archive (placeholder - not yet implemented)
- **`.7z`** - 7-Zip archive (placeholder - not yet implemented)
- **`.tar`** - TAR archive (placeholder - not yet implemented)
- **`.gz`** - GZIP compressed file (placeholder - not yet implemented)
- **`.bz2`** - BZIP2 compressed file (placeholder - not yet implemented)
- **`.xz`** - XZ compressed file (placeholder - not yet implemented)

### 📊 Data Formats
- **`.db`** - SQLite database (requires sqlite3)
- **`.sqlite`** - SQLite database (requires sqlite3)
- **`.sqlite3`** - SQLite database (requires sqlite3)
- **`.mdb`** - Microsoft Access database (binary scan)
- **`.accdb`** - Microsoft Access database (binary scan)

### 🖼️ Media Formats
- **Images**: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.tiff`, `.tif`, `.webp`
- **Audio**: `.mp3`, `.wav`, `.flac`, `.aac`, `.ogg`, `.wma`, `.m4a`
- **Video**: `.mp4`, `.avi`, `.mkv`, `.mov`, `.wmv`, `.flv`, `.webm`, `.m4v`

*Note: Media files are processed for metadata and embedded text only.*

### 📝 Text Formats
- **`.txt`** - Plain text files
- **`.log`** - Log files
- **`.csv`** - Comma-separated values
- **`.json`** - JSON data files
- **`.xml`** - XML files
- **`.html`** - HTML files
- **`.htm`** - HTML files
- **`.yaml`** - YAML files
- **`.yml`** - YAML files
- **`.md`** - Markdown files
- **`.rst`** - reStructuredText files
- **`.tex`** - LaTeX files
- **`.rtf`** - Rich Text Format
- **`.conf`** - Configuration files
- **`.cfg`** - Configuration files
- **`.ini`** - Initialization files

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Start
```bash
# Clone the repository
git clone https://github.com/your-org/project-revelare.git
cd project-revelare

# Install dependencies
pip install -r requirements.txt

# Run the complete CLI maestro
python revelare_onboard.py

# Or run the web interface
python suite.py

# Or use the command-line interface
python revelare_cli.py --help
```

### Dependencies
- Flask (web framework)
- requests (HTTP client)
- PyPDF2 (PDF processing)
- python-docx (Word document processing)
- openpyxl (Excel processing)
- pandas (Excel and data processing)
- ipaddress (IP address handling)

### Optional Dependencies
To get full support for all formats, install these optional packages:

```bash
# Email processing
pip install pywin32  # For .msg files on Windows
pip install extract-msg  # Alternative .msg processor

# Archive processing
pip install py7zr  # For .7z files
pip install rarfile  # For .rar files

# Image processing
pip install Pillow  # For image metadata extraction

# Audio/Video processing
pip install mutagen  # For audio metadata
pip install ffmpeg-python  # For video metadata
```

## 🚀 Usage

### Complete CLI Maestro (Recommended)
The easiest way to use Project Revelare is through the complete CLI maestro:

```bash
# Complete maestro (onboarding + processing)
python revelare_onboard.py

# Just onboarding (no evidence processing)
python revelare_onboard.py --onboard-only

# Show help
python revelare_onboard.py --help
```

The maestro will:
1. Collect case information (investigator, agency, case details)
2. Create project structure
3. Collect evidence files (with wildcard support)
4. Process evidence files using the existing CLI
5. Generate comprehensive reports
6. Display results with file sizes and locations

### Web Interface
1. Start the web server: `python suite.py`
2. Open your browser to `http://localhost:5000`
3. Upload files using the drag-and-drop interface
4. View results in the interactive dashboard
5. Export data in various formats

### Command Line Interface
```bash
# Basic usage
python revelare_cli.py -p "my_project" -f "evidence.txt"

# Process multiple files
python revelare_cli.py -p "my_project" -f "file1.txt" "file2.pdf" "file3.zip"

# Verbose output
python revelare_cli.py -p "my_project" -f "evidence.txt" -v

# Help
python revelare_cli.py --help
```

### Programmatic Usage
```python
from extractor import run_extraction
from reporter import generate_report

# Extract indicators from files
findings = run_extraction(["evidence1.txt", "evidence2.pdf"])

# Generate HTML report
report_html = generate_report("my_project", findings)
```

## 📊 Report Features

### Interactive HTML Reports
- **Executive Summary**: High-level overview of findings
- **Detailed Analysis**: Category-by-category breakdown
- **Geographical Mapping**: IP address locations on maps
- **Network Visualization**: Network topology and relationships
- **Timeline Analysis**: Chronological event correlation
- **Statistical Dashboards**: Charts and metrics

### Export Formats
- **JSON**: Machine-readable structured data
- **CSV**: Spreadsheet-compatible format
- **Legal Warrant**: Specialized format for legal proceedings

## 🔒 Security Features

### Input Validation
- File type validation and scanning
- Path traversal protection
- Malicious file detection
- File size limits

### Output Sanitization
- HTML output sanitization
- XSS prevention
- SQL injection protection
- Data validation and cleaning

### Access Control
- Secure file handling
- Temporary file management
- Safe extraction processes
- Audit logging

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python -m unittest discover tests

# Run specific test modules
python -m unittest tests.test_extractor
python -m unittest tests.test_security
python -m unittest tests.test_data_enhancer

# Run with coverage
python -m pytest tests/ --cov=.
```

### Test Coverage
- **Unit Tests**: Individual module testing
- **Integration Tests**: End-to-end functionality
- **Security Tests**: Vulnerability testing
- **Performance Tests**: Load and stress testing

## 📁 Project Structure

```
project-revelare/
├── extractor.py              # Core extraction logic
├── reporter.py               # Report generation
├── suite.py                  # Web interface
├── revelare_cli.py          # Command-line interface
├── revelare_onboard.py      # Complete CLI maestro
├── security.py              # Security utilities
├── data_enhancer.py         # Data filtering and enhancement
├── legal_export.py          # Legal warrant export
├── logger.py                # Logging system
├── config.py                # Configuration management
├── constants.py             # Centralized constants
├── file_extractor.py        # File extraction utilities
├── monitor_process.py       # Process monitoring tool
├── tests/                   # Test suite
│   ├── test_extractor.py
│   ├── test_security.py
│   ├── test_data_enhancer.py
│   └── test_integration.py
├── output/                  # Generated reports and data
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore file
└── README.md               # This file
```

## 🔧 Configuration

### Environment Variables
- `REVELARE_DEBUG`: Enable debug mode
- `REVELARE_LOG_LEVEL`: Set logging level
- `REVELARE_MAX_FILE_SIZE`: Maximum file size limit
- `REVELARE_OUTPUT_DIR`: Output directory path

### Configuration File
Create `config.ini` for custom settings:
```ini
[general]
debug = false
log_level = INFO
max_file_size = 100MB

[security]
allowed_extensions = .txt,.pdf,.docx,.xlsx,.json,.csv,.zip,.eml,.msg
max_files_per_upload = 100

[output]
default_format = html
include_geolocation = true
```

## 📚 API Documentation

### Core Modules

#### Extractor Module (`extractor.py`)

##### `classify_ip(ip: str) -> str`
Classifies an IP address into its type category.

**Parameters:**
- `ip` (str): IP address to classify (may include port)

**Returns:**
- `str`: Classification ("Private", "Public", "Loopback", "Multicast", "Reserved/Bogus", "Invalid")

**Example:**
```python
from extractor import classify_ip

result = classify_ip("192.168.1.1")
print(result)  # "Private"

result = classify_ip("8.8.8.8:53")
print(result)  # "Public"
```

##### `find_matches_in_text(text: str, file_name: str) -> Dict[str, Dict[str, str]]`
Finds indicators of compromise in text content using regex patterns.

**Parameters:**
- `text` (str): Text content to search
- `file_name` (str): Name of the file being processed

**Returns:**
- `Dict[str, Dict[str, str]]`: Dictionary of findings by category

**Example:**
```python
from extractor import find_matches_in_text

text = "IP: 192.168.1.1, Email: test@example.com"
findings = find_matches_in_text(text, "test.txt")
print(findings)
# {
#     "IPv4": {"192.168.1.1": "File: test.txt | Position: 4 | Type: Private"},
#     "Email_Addresses": {"test@example.com": "File: test.txt | Position: 25"}
# }
```

##### `run_extraction(input_files: List[str]) -> Dict[str, Dict[str, str]]`
Main entry point for running extraction on multiple files.

**Parameters:**
- `input_files` (List[str]): List of file paths to process

**Returns:**
- `Dict[str, Dict[str, str]]`: Consolidated findings from all files

**Example:**
```python
from extractor import run_extraction

files = ["evidence1.txt", "evidence2.pdf", "evidence3.zip"]
results = run_extraction(files)
print(results["Processing_Summary"])
# {
#     "Total_Files_Processed": "3",
#     "Total_Files_Failed": "0",
#     "Total_Files_Skipped": "0",
#     "Processing_Time_Seconds": "1.23"
# }
```

#### Reporter Module (`reporter.py`)

##### `generate_report(project_name: str, findings: Dict[str, Dict[str, str]]) -> str`
Generates an interactive HTML report from extraction findings.

**Parameters:**
- `project_name` (str): Name of the project
- `findings` (Dict[str, Dict[str, str]]): Findings from extraction

**Returns:**
- `str`: HTML content of the generated report

**Example:**
```python
from reporter import generate_report
from extractor import run_extraction

findings = run_extraction(["evidence.txt"])
report_html = generate_report("my_project", findings)

# Save to file
with open("report.html", "w", encoding="utf-8") as f:
    f.write(report_html)
```

#### Security Module (`security.py`)

##### `SecurityValidator` Class

##### `sanitize_filename(filename: str) -> str`
Sanitizes filenames to prevent path traversal attacks.

**Parameters:**
- `filename` (str): Original filename

**Returns:**
- `str`: Sanitized filename

**Example:**
```python
from security import SecurityValidator

safe_name = SecurityValidator.sanitize_filename("../../../etc/passwd")
print(safe_name)  # "etc_passwd"
```

##### `validate_file_extension(filename: str) -> Tuple[bool, str]`
Validates file extensions against allowed types.

**Parameters:**
- `filename` (str): Filename to validate

**Returns:**
- `Tuple[bool, str]`: (is_valid, message)

**Example:**
```python
from security import SecurityValidator

is_valid, message = SecurityValidator.validate_file_extension("document.pdf")
print(is_valid)  # True
print(message)   # "Valid"
```

### Web API Endpoints

#### Main Dashboard
- **URL:** `GET /`
- **Description:** Main project dashboard
- **Response:** HTML page with project list and upload form

#### File Upload
- **URL:** `POST /`
- **Description:** Upload and process files
- **Parameters:**
  - `project_name` (str): Name of the project
  - `files` (List[File]): Files to upload
- **Response:** Redirect to project page or error message

#### Link Analysis
- **URL:** `GET /link_analysis`
- **Description:** Link analysis interface
- **Response:** HTML page with search form

#### Search Indicators
- **URL:** `POST /link_analysis`
- **Description:** Search for indicators across projects
- **Parameters:**
  - `search_term` (str): Term to search for
- **Response:** HTML page with search results

#### Export Data
- **URL:** `GET /export/<project>/<format>`
- **Description:** Export project data
- **Parameters:**
  - `project` (str): Project name
  - `format` (str): Export format (json, csv, warrant)
- **Response:** File download or JSON data

#### Project Details
- **URL:** `GET /project/<project>`
- **Description:** View project details and results
- **Response:** HTML page with project information

## 🔧 Processing Methods

### Direct Text Processing
Files that are already in text format are processed directly:
- Text files, logs, CSV, JSON, XML, HTML, YAML, Markdown, etc.
- EML files (email format)
- Mbox files (mailbox format)

### Library-Based Processing
Files that require special libraries for text extraction:
- PDF files (PyPDF2)
- Word documents (python-docx)
- Excel spreadsheets (pandas)
- SQLite databases (sqlite3)

### Binary Scanning
Files that don't have direct text extraction support:
- Outlook message files (.msg) - fallback to binary scan
- Outlook data files (.pst, .ost)
- Media files (images, audio, video)
- Other binary formats

## 🚨 Error Handling

### Common Exceptions

#### `FileNotFoundError`
Raised when input files don't exist.
```python
try:
    results = run_extraction(["nonexistent.txt"])
except FileNotFoundError as e:
    print(f"File not found: {e}")
```

#### `ValueError`
Raised when invalid parameters are provided.
```python
try:
    results = run_extraction([])  # Empty list
except ValueError as e:
    print(f"Invalid input: {e}")
```

#### `SecurityError`
Raised when security validation fails.
```python
from security import SecurityValidator

try:
    is_valid, message = SecurityValidator.validate_file_extension("malware.exe")
    if not is_valid:
        raise SecurityError(message)
except SecurityError as e:
    print(f"Security validation failed: {e}")
```

## 🔍 Troubleshooting

### Common Issues

#### "File type not allowed" Error
- Check that file extension is in allowed list
- Verify file is not corrupted
- Ensure file is not a nested archive

#### "Path traversal detected" Error
- Check filename for suspicious characters
- Ensure file is in allowed directory
- Verify file path is properly sanitized

#### "Memory error" During Processing
- Reduce file size or process in smaller chunks
- Increase available memory
- Check for memory leaks in processing

#### "No indicators found" Result
- Verify file contains text content
- Check file encoding (UTF-8 recommended)
- Ensure file is not password protected

### Debug Mode
Enable debug mode for detailed logging:
```python
import os
os.environ['REVELARE_DEBUG'] = 'true'
```

### Log Analysis
Check logs for detailed error information:
```bash
tail -f revelare.log
```

### Process Monitoring
Use the built-in process monitor to check if processing is hung:
```bash
python monitor_process.py
```

### Development Setup
```bash
# Clone the repository
git clone https://github.com/your-org/project-revelare.git
cd project-revelare

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m unittest discover tests
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Digital forensics community for feedback and testing
- Open source libraries and tools that make this project possible
- Security researchers who contributed to threat intelligence

## 📈 Roadmap

### Version 2.2 (Planned)
- [ ] Machine learning-based indicator classification
- [ ] Advanced timeline correlation
- [ ] API endpoints for integration
- [ ] Docker containerization
- [ ] Database backend options

### Version 3.0 (Future)
- [ ] Real-time monitoring capabilities
- [ ] Cloud deployment options
- [ ] Advanced visualization features
- [ ] Multi-user collaboration
- [ ] Enterprise features

---

**Project Revelare** - *Unveiling the truth in digital evidence*

For more information, visit [project-revelare.com](https://project-revelare.com)
