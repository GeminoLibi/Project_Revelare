# Unified Case Management System

## Overview

Project Revelare now includes a unified case management system that integrates:
- **Case Discovery**: Automatically finds cases in external directories
- **Duplicate Detection**: Prevents duplicate files using quick hash (size+mtime) and full hash (SHA256)
- **Cross-Case Duplicate Detection**: Flags duplicate files across different cases
- **Truleo Conversion**: Optional file conversion to Truleo-accepted formats
- **Scheduled Synchronization**: Weekly automated scans

## Components

### 1. File Deduplication (`revelare/utils/file_deduplication.py`)

Provides hash-based duplicate detection:
- **Quick Hash**: Uses file size + modification time for fast initial filtering
- **Full Hash**: SHA256 for definitive duplicate detection
- **Cross-Case Detection**: Finds duplicate files across different case directories

### 2. Case Synchronization (`revelare/utils/case_sync.py`)

Synchronizes external case directories with Project Revelare:
- Discovers cases in nested directory structures (category/case)
- Creates new cases automatically
- Processes new files incrementally
- Checks for duplicates before adding files

### 3. Truleo Converter (`revelare/utils/truleo_converter.py`)

Converts case files to Truleo-accepted formats:
- Integrates with UniversalFileConverter (UFC)
- Converts files to most accessible Truleo format
- Handles parallel conversion for performance

### 4. Unified Manager (`revelare/utils/unified_manager.py`)

Orchestrates all components:
- Runs complete synchronization workflow
- Coordinates duplicate detection
- Manages Truleo conversion (optional)
- Provides comprehensive reporting

## Usage

### Manual Synchronization

```bash
python run_case_sync.py [external_cases_dir]
```

This will:
1. Discover cases in the external directory
2. Create missing cases in Project Revelare
3. Check for duplicates before adding files
4. Process new files found
5. Check for cross-case duplicates
6. Generate duplicate report if found

### Scheduled Synchronization

The `schedule_case_sync.py` script is designed to run via Windows Task Scheduler:

```bash
python schedule_case_sync.py
```

Or set up via Task Scheduler using `create_sync_task.bat`.

### Using the Unified Manager Directly

```python
from revelare.utils.unified_manager import UnifiedCaseManager

manager = UnifiedCaseManager(external_cases_dir=r"E:\Cases")

# Run full sync with all features
results = manager.run_full_sync(
    process_files=True,
    check_duplicates=True,
    check_cross_case_duplicates=True,
    convert_to_truleo=False  # Set to True to enable conversion
)

# Or run weekly scan (same as scheduled sync)
results = manager.run_weekly_scan()
```

## Duplicate Detection

### How It Works

1. **Quick Hash Check**: Files are first checked using size + mtime (fast)
2. **Full Hash Verification**: If quick hash matches, SHA256 is computed for verification
3. **Duplicate Skipping**: Duplicate files are skipped during sync
4. **Cross-Case Detection**: After sync, all cases are scanned for duplicates

### Duplicate Reports

Duplicate reports are saved to:
- `cases/duplicate_report_YYYYMMDD_HHMMSS.txt`

Reports include:
- File hash
- File size
- All locations where duplicate was found (case name and path)

## File Conversion (Truleo)

### Enabling Truleo Conversion

Set `convert_to_truleo=True` when calling `run_full_sync()`:

```python
results = manager.run_full_sync(convert_to_truleo=True)
```

### Conversion Output

Converted files are placed in:
- `cases/{case_name}/truleo/` (default)
- Or custom output directory if specified

Files are renamed with case prefix: `{case_name}_{original_name}.{ext}`

## Configuration

### Environment Variables

- `REVELARE_EXTERNAL_CASES_DIR`: External cases directory (default: `E:\Cases`)
- `REVELARE_SYNC_PROCESS_FILES`: Process new files (default: `true`)

### Directory Structure

The system expects external cases in this structure:
```
E:\Cases\
  ├── Category1\
  │   ├── Case1\
  │   ├── Case2\
  │   └── ...
  ├── Category2\
  │   ├── Case3\
  │   └── ...
  └── ...
```

Cases are identified by their directory names (e.g., `Case1`, `Case2`).

## Statistics and Reporting

The unified system provides comprehensive statistics:

```python
{
    'sync_stats': {
        'cases_discovered': 58,
        'cases_created': 5,
        'cases_updated': 10,
        'files_processed': 150,
        'duplicates_skipped': 12,
        'cross_case_duplicates': 3,
        'duplicate_report_file': 'cases/duplicate_report_20251223_110000.txt'
    },
    'duplicate_report': {
        'file': 'cases/duplicate_report_20251223_110000.txt',
        'duplicate_groups': 3,
        'report': '...'
    },
    'truleo_conversions': {
        'case1': {'converted': 50, 'failed': 2, 'skipped': 5},
        'case2': {'converted': 30, 'failed': 1, 'skipped': 3}
    },
    'errors': []
}
```

## Performance Considerations

- **Quick Hash**: Very fast, used for initial filtering
- **Full Hash**: Computed only for potential matches (saves time)
- **Parallel Processing**: Truleo conversion uses parallel processing
- **Incremental Processing**: Only new files are processed (tracked by hash)

## Troubleshooting

### UFC Not Found

If Truleo conversion fails with "UFC converter not available":
- Ensure UniversalFileConverter exists at `E:\Scripts\UniversalFileConverter`
- Check that `file_converter.py` is present

### Duplicate Detection Slow

For very large case directories:
- Quick hash index is built once per sync
- Full hash is only computed for potential matches
- Consider excluding large directories (logs, exports) from scanning

### Cross-Case Duplicates Report

If you see many duplicates:
- Review the duplicate report file
- Check if files were accidentally copied between cases
- Verify no filing errors occurred

## Best Practices

1. **Run Weekly Scans**: Use scheduled sync to keep cases up-to-date
2. **Review Duplicate Reports**: Check for filing errors or data issues
3. **Monitor Errors**: Review error logs for processing issues
4. **Backup Before Conversion**: Truleo conversion creates new files (original preserved)
5. **Exclude Temp Directories**: Skip temp, logs, exports from processing

