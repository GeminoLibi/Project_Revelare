# Project Revelare - Full Documentation

## Table of Contents

1. [Installation and Setup](installation.md)
2. [User Guide](user_guide.md)
3. [Case Management](case_management.md)
4. [Case Synchronization](case_synchronization.md)
5. [File Processing](file_processing.md)
6. [Report Generation](report_generation.md)
7. [CLI Reference](cli_reference.md)
8. [Web Interface](web_interface.md)
9. [API Reference](api_reference.md)
10. [Configuration](configuration.md)
11. [Troubleshooting](troubleshooting.md)

## Overview

Project Revelare is a comprehensive digital forensics platform designed for extracting, analyzing, and reporting on indicators of compromise (IOCs) from various file types and data sources.

### Core Capabilities

- **Multi-Format File Processing**: Supports text, documents, emails, archives, images, audio, video, and binary files
- **Intelligent IOC Extraction**: Extracts IPs, domains, emails, credit cards, crypto addresses, phone numbers, and more
- **GeoIP Enrichment**: Automatically enriches IP addresses with geographic and ASN data
- **Case Management**: Full case lifecycle management with metadata tracking
- **Duplicate Detection**: Hash-based duplicate detection prevents redundant processing
- **Case Synchronization**: Automatically discover and sync cases from external directories
- **Report Generation**: Comprehensive HTML reports with interactive dashboards
- **Export Options**: Export reports as portable packages, JSON, CSV, or warrant formats

## Quick Links

- [Installation Guide](installation.md) - Get started quickly
- [User Guide](user_guide.md) - Learn how to use Revelare
- [CLI Reference](cli_reference.md) - Command-line interface documentation
- [Web Interface](web_interface.md) - Web UI documentation

## Architecture

Project Revelare follows a modular architecture:

- **Core Processing**: `revelare/core/` - Extraction engines and file processors
- **Case Management**: `revelare/core/case_manager.py` - Case lifecycle management
- **Utilities**: `revelare/utils/` - Sync, deduplication, conversion, reporting
- **Interfaces**: `revelare/cli/` - CLI and web interfaces
- **Configuration**: `revelare/config/` - Settings and regex patterns

## Key Concepts

### Cases

A case represents a digital forensics investigation. Each case contains:
- Source path/hash audit records (`ingest_manifest.json`) instead of a permanent document vault
- Extracted indicators
- Reports
- Metadata

Older cases may still contain files under `evidence/` or `extracted_files/`. New ingest does not add copies there and does not mass-delete those legacy copies.

### Indicators

Indicators (IOCs) are extracted from evidence files using regex patterns. Categories include:
- Network indicators (IPs, domains, URLs)
- Financial indicators (credit cards, crypto addresses)
- Personal information (emails, phone numbers, SSNs)
- Security indicators (hashes, API keys, tokens)

### Processing Pipeline

1. **Ingestion**: Files are staged to a temp directory (not copied into the case vault)
2. **Extraction**: Archives are extracted in temp, files are processed
3. **Analysis**: IOCs are extracted using regex patterns; each finding records SourcePath/SourceHash
4. **Cleanup**: The temp copy is deleted
5. **Enrichment**: IPs are enriched with GeoIP data
6. **Reporting**: Reports are generated with findings
7. **Export**: Reports can be exported in various formats

## Getting Help

- Check the [Troubleshooting Guide](troubleshooting.md)
- Review [Configuration](configuration.md) for settings
- See [API Reference](api_reference.md) for programmatic access

