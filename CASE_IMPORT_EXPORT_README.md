# Case Import/Export System

## Overview

Project Revelare now includes a standardized case import/export system that allows you to:
- Export cases with all files (full export)
- Export cases with only indicators (lightweight export)
- Import cases from exported files
- Share cases between different Revelare installations

## Export Formats

### Full Export
Includes:
- Case metadata (`case_metadata.json`)
- All extracted indicators (`raw_findings.json`)
- Evidence files (from `evidence/` directory)
- Extracted files (from `extracted_files/` directory, optional)
- Reports and optional files

**Use when:** You need to share a complete case with all evidence files.

### Indicators-Only Export
Includes:
- Case metadata (`case_metadata.json`)
- All extracted indicators (`raw_findings.json`)
- Reports and optional files
- **No evidence files**

**Use when:** You only need to share the analysis results, not the source files (smaller file size).

## Usage

### Web Interface

#### Export a Case

1. Navigate to **Case Management** for the case you want to export
2. Click the **Export Case** dropdown button
3. Choose:
   - **Full Export (with files)** - Includes all evidence files
   - **Indicators Only** - Only extracted indicators

4. The export will be created in the case's `exports/` directory
5. Download the `.zip` file when ready

#### Import a Case

1. From the **Dashboard**, click **Import Case**
2. Select the export `.zip` file
3. (Optional) Enter a new case name (or leave empty to use original name)
4. (Optional) Check "Overwrite existing case" if you want to replace an existing case
5. Click **Import Case**

### Command Line Interface

#### Export a Case

**Full export:**
```bash
python -m revelare.cli.revelare_cli --export-case "case_name"
```

**Indicators-only export:**
```bash
python -m revelare.cli.revelare_cli --export-case "case_name" --export-indicators-only
```

**Custom output location:**
```bash
python -m revelare.cli.revelare_cli --export-case "case_name" --export-output "C:\Exports"
```

**Exclude extracted files:**
```bash
python -m revelare.cli.revelare_cli --export-case "case_name" --export-no-extracted
```

#### Import a Case

**Basic import:**
```bash
python -m revelare.cli.revelare_cli --import-case "path/to/export.zip"
```

**Import with new name:**
```bash
python -m revelare.cli.revelare_cli --import-case "export.zip" --import-name "new_case_name"
```

**Import with overwrite:**
```bash
python -m revelare.cli.revelare_cli --import-case "export.zip" --import-overwrite
```

## Export File Structure

Exported `.zip` files contain:

```
case_name/
├── export_manifest.json      # Export metadata and manifest
├── case_metadata.json        # Case metadata (required)
├── raw_findings.json         # Extracted indicators (required)
├── report.html               # Generated report (if exists)
├── indicators.json           # Indicators in JSON format (if exists)
├── indicators.csv            # Indicators in CSV format (if exists)
├── evidence/                 # Evidence files (full export only)
│   └── ...
└── extracted_files/          # Extracted files (full export, optional)
    └── ...
```

## Export Manifest

Each export includes a `export_manifest.json` file with metadata:

```json
{
  "format_version": "1.0",
  "export_type": "full",
  "case_name": "case_001",
  "export_date": "2025-01-15T10:30:00",
  "revelare_version": "2.5",
  "includes_files": true,
  "includes_extracted": true,
  "indicators_count": 1250,
  "categories": ["IPv4", "Email_Addresses", "URLs"],
  "files": {
    "evidence_count": 45,
    "extracted_count": 120
  }
}
```

## Import Process

When importing a case:

1. **Validation:** The export file is validated for required files
2. **Manifest Check:** Export format version is checked
3. **Case Creation:** Case directory is created (or overwritten if specified)
4. **File Copying:** All files and directories are copied
5. **Metadata Update:** Import information is added to case metadata

## Use Cases

### Sharing Cases Between Teams

1. Export the case (full or indicators-only based on needs)
2. Share the `.zip` file via secure channel
3. Recipient imports the case into their Revelare installation
4. Case is immediately available for analysis

### Backup and Archive

1. Export cases regularly for backup
2. Store exports in secure archive location
3. Restore by importing when needed

### Case Transfer

1. Export case from old system
2. Import into new system
3. All indicators and metadata preserved

### Lightweight Sharing

1. Export indicators-only for cases with large evidence files
2. Share analysis results without sharing source files
3. Recipient can view all extracted indicators and reports

## Notes

- **File Size:** Full exports can be large if cases contain many files. Use indicators-only for smaller exports.
- **Case Names:** Imported cases use the original name unless a new name is specified.
- **Overwrite Protection:** By default, importing will fail if a case with the same name exists. Use `--import-overwrite` to replace.
- **Format Version:** Exports are versioned. Future versions may add new features while maintaining backward compatibility.
- **Required Files:** Both `case_metadata.json` and `raw_findings.json` are required for a valid export.

## Troubleshooting

### "Missing required files" error
- Ensure the case has been processed (has `raw_findings.json`)
- Check that `case_metadata.json` exists

### "Case already exists" error
- Use `--import-overwrite` flag or check "Overwrite existing case" in web interface
- Or specify a different case name with `--import-name`

### Import fails silently
- Check that the export file is a valid `.zip` file
- Verify the export file wasn't corrupted during transfer
- Check logs for detailed error messages

### Large export files
- Use indicators-only export for smaller file sizes
- Consider excluding `extracted_files` directory with `--export-no-extracted`
- Compress exports further if needed (they're already zipped)

## API Reference

### CaseExporter

```python
from revelare.utils.case_import_export import CaseExporter

exporter = CaseExporter()
success, message, export_path = exporter.export_case(
    case_name="case_001",
    output_path="exports/",
    include_files=True,
    include_extracted=True
)
```

### CaseImporter

```python
from revelare.utils.case_import_export import CaseImporter

importer = CaseImporter()
success, message, case_path = importer.import_case(
    export_file_path="export.zip",
    target_case_name=None,  # Use original name if None
    overwrite=False
)
```

### Validation

```python
from revelare.utils.case_import_export import CaseImporter

importer = CaseImporter()
is_valid, message, manifest = importer.validate_export_file("export.zip")
```
