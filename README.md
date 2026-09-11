# Project Revelare

**Digital Forensics and Intelligence Extraction Platform**

Project Revelare is a comprehensive digital forensics tool designed for extracting, analyzing, and reporting on indicators of compromise (IOCs) from various file types and data sources.

## Quick Start

### Installation

**Option 1: Standalone .exe (Windows - Easiest for End Users)**

```batch
# Build the executable (one-time setup)
utilities\build_exe.bat

# The executable will be in dist/ProjectRevelare.exe (gitignored)
# Just double-click to run - no Python or dependencies needed!
```

See [EXE_BUILD_README.md](EXE_BUILD_README.md) for detailed build instructions.

**Option 2: Docker (Recommended for Easy Sharing)**

```bash
# Clone the repository
git clone https://github.com/yourusername/project_revelare.git
cd project_revelare

# Build and run with Docker Compose
docker-compose up -d

# Access at http://localhost:5000
```

**Option 3: Local Python Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/project_revelare.git
cd project_revelare

# Install dependencies
pip install -r requirements.txt

# Set up GeoIP databases (optional but recommended)
# Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb to project root
```

### Docker Usage

**Starting the container:**
```bash
docker-compose up -d
```

**Viewing logs:**
```bash
docker-compose logs -f
```

**Stopping the container:**
```bash
docker-compose down
```

**Running CLI commands:**
```bash
# Execute CLI commands inside the container
docker-compose exec revelare python -m revelare.cli.revelare_cli --onboard
```

**Building the image manually:**
```bash
docker build -t project-revelare .
docker run -p 5000:5000 -v $(pwd)/cases:/app/cases -v $(pwd)/logs:/app/logs project-revelare
```

### Basic Usage

**Web Interface:**
```bash
python start.py
# Choose option 1: Web Interface
# Access at http://localhost:5000
```

**CLI:**
```bash
# Create a new case
python -m revelare.cli.revelare_cli --onboard

# Process files
python -m revelare.cli.revelare_cli -p "case_001" -f evidence.zip

# Synchronize cases from an external directory
python -m revelare.cli.revelare_cli --sync "C:\path\to\cases"
```

## Key Features

- **No permanent document copies**: Ingest stages a temp copy, extracts IOCs, records the original source path/hash, then deletes the temp file. The case vault stores metadata and findings, not a second copy of the document.
- **Multi-Format Support**: Processes text, documents, emails, archives, images, audio, video, and more
- **Intelligent Extraction**: Extracts IOCs including IPs, domains, emails, credit cards, crypto addresses, and more
- **GeoIP Enrichment**: Automatically enriches IP addresses with geographic and ASN data
- **Case Management**: Full case lifecycle management with metadata tracking
- **Duplicate Detection**: Hash-based duplicate detection prevents redundant processing
- **Case Synchronization**: Automatically discover and sync cases from external directories
- **Report Generation**: Comprehensive HTML reports with interactive dashboards
- **Export Options**: Export reports as portable packages, JSON, CSV, or warrant formats
- **Truleo Integration**: Convert files to Truleo-accepted formats for SaaS platforms

## Ingest and audit paths

New ingest does **not** keep a forensic copy under `cases/<case>/evidence/` or `extracted_files/`.

Each processed document is copied to a temp directory, hashed, parsed, then the temp copy is deleted (`try`/`finally`). Audit data is stored on the findings and in `cases/<case>/ingest_manifest.json`:

- `SourcePath` - original filesystem path (CLI/sync) or `upload://original-filename` (web upload)
- `SourceHash` - SHA-256 of the source file
- `SourceMtime` / timestamps - source file times and ingest time

CSV exports include `SourcePath` and `SourceHash` columns. The SQLite master DB stores the same fields on each indicator.

**Existing cases:** copies already sitting in `evidence/` or `extracted_files/` are left in place. Revelare does not mass-delete prior vault copies. Purge those directories yourself if you want them gone.

**Re-analysis:** for new ingest, re-analysis re-reads the original source path if it still exists. Web-only uploads have no original path, so re-upload to process again.

## Documentation

For detailed documentation, see:
- **[Full Documentation](docs/README.md)** - Complete user guide and API reference
- **[Case Synchronization](CASE_SYNC_README.md)** - Case sync and duplicate detection
- **[Unified System](UNIFIED_SYSTEM_README.md)** - Integrated case management system
- **[Docker Setup](DOCKER_README.md)** - Docker installation and usage
- **[Building .exe](EXE_BUILD_README.md)** - Creating standalone Windows executable

## Project Structure

```
project_revelare/
├── revelare/              # Core package
│   ├── core/             # Processing engines
│   ├── cli/              # CLI and web interfaces
│   ├── utils/            # Utilities (sync, deduplication, conversion)
│   ├── web/              # Web templates and static files
│   └── config/           # Configuration
├── utilities/             # Optional helpers (exe build, batch clean)
├── docs/                  # Documentation
└── requirements.txt       # Python dependencies
```

## Requirements

- Python 3.8+
- See `requirements.txt` for full dependency list
- GeoLite2 databases (optional) for IP enrichment

## License

See LICENSE file for details.

## Contributing

Contributions welcome! Please see CONTRIBUTING.md for guidelines.

## Support

For issues, questions, or contributions, please open an issue on GitHub.
