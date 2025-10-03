# Project Revelare v2.3

**Advanced Digital Forensics and Incident Response Platform**

A comprehensive forensic analysis tool designed to extract, analyze, and report on digital evidence from multiple file formats. Built for law enforcement, incident response teams, and digital forensics professionals.

## 🚀 Key Features

### Core Capabilities
- **Multi-Format Support**: Process 40+ file types including TXT, PDF, DOCX, XLSX, JSON, CSV, ZIP, EML, MSG, and more
- **Advanced IOC Extraction**: Identify 15+ types of indicators including IPs, emails, URLs, file paths, and more
- **Intelligent Filtering**: Remove irrelevant data and false positives automatically
- **Robust Schema**: Database designed to store all enriched metadata (Confidence, Ports, Timestamps)
- **Real-time Processing**: Live progress monitoring and status updates
- **Comprehensive Reporting**: Generate detailed HTML reports with enriched data

### Supported File Types
- **Documents**: PDF, DOCX, XLSX, PPTX, RTF, TXT
- **Archives**: ZIP, RAR, 7Z, TAR, GZ
- **Email**: EML, MSG, PST
- **Data**: JSON, CSV, XML, LOG
- **Media**: Images, Audio, Video files
- **System**: Executables, Scripts, Config files

### Forensic Indicators
- Email Addresses and Headers
- IP Addresses (IPv4/IPv6)
- URLs and Domains
- Phone Numbers
- Credit Card Numbers
- Device IDs and UUIDs
- File Paths and Timestamps
- User Agents and Tokens
- Process Names and Connection Info

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (recommended)
- 4GB+ RAM
- 1GB+ free disk space

### Quick Start
```bash
# Clone the repository
git clone https://github.com/your-org/project-revelare.git
cd project-revelare

# Install dependencies
pip install -r requirements.txt

# Run interactive onboarding wizard
python revelare_cli.py --onboard

# Or process files directly
python revelare_cli.py -p "case_name" -f "evidence1.zip" "evidence2.zip" -o "output_dir"

# Or run the web interface
python suite.py
```

## 📖 Usage

### Interactive Onboarding
```bash
python revelare_cli.py --onboard
```
This launches an interactive wizard that:
- Collects case metadata (investigator, agency, case info)
- Creates organized project structure
- Guides evidence file placement
- Generates processing scripts

### Direct Processing
```bash
# Process single file
python revelare_cli.py -p "case_001" -f evidence.zip

# Process multiple files
python revelare_cli.py -p "case_001" -f file1.zip file2.pdf file3.msg -o analysis

# With verbose logging
python revelare_cli.py -p "case_001" -f evidence.zip --verbose

# With debug logging
python revelare_cli.py -p "case_001" -f evidence.zip --debug
```

### Web Interface
```bash
python suite.py
```
Access the web interface at `http://localhost:5000` for:
- File upload and processing
- Real-time progress monitoring
- Report viewing and export
- Case management

## 📁 Project Structure

```
project_revelare/
├── cases/                          # Case directories
│   └── [case_name]/
│       ├── evidence/               # Evidence files
│       ├── analysis/               # Processing results
│       ├── extracted_files/        # Extracted content
│       ├── reports/                # Generated reports
│       ├── logs/                   # Case-specific logs
│       └── process_case.py         # Auto-generated processing script
├── revelare_cli.py                 # Main CLI interface
├── suite.py                        # Web interface
├── extractor.py                    # Core extraction engine
├── reporter.py                     # Report generation
├── file_extractor.py               # File handling utilities
├── security.py                     # Security validation
├── logger.py                       # Logging system
└── requirements.txt                # Dependencies
```

## 🔧 Configuration

### File Size Limits
- Default max file size: 100MB
- Override with `--max-size` parameter
- Large files are processed in chunks

### Processing Options
- `--verbose`: Enable detailed logging
- `--debug`: Enable debug mode with full tracebacks
- `--output`: Specify output directory
- `--project`: Set project/case name

## 📊 Output

### Generated Files
- **indicators.json**: Raw extracted indicators
- **indicators.csv**: Tabular format for analysis
- **report.html**: Comprehensive forensic report
- **raw_findings.json**: Complete analysis results

### Report Contents
- Executive summary
- Indicator counts by type
- Enriched IP address data
- File processing statistics
- Timeline analysis
- Exportable data tables

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
- Create an issue on GitHub
- Contact the development team
- Check the troubleshooting section

## 🔄 Version History

- **v2.3**: Enhanced processing, improved error handling, real-time monitoring
- **v2.2**: Added web interface, improved reporting
- **v2.1**: Enhanced extraction capabilities
- **v2.0**: Complete rewrite with new architecture