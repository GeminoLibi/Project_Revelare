# Case Synchronization Feature

Automatically sync cases from an external directory (e.g., `E:\Cases`) with Project Revelare.

## Features

- **Auto-discovery**: Scans external directory for case folders
- **Auto-creation**: Creates new cases in Project Revelare for cases that don't exist
- **Incremental processing**: Only processes new files (tracks processed files)
- **Scheduled execution**: Can run automatically on a schedule

## Usage

### Manual Sync

```bash
python -m revelare.cli.revelare_cli --sync "C:\path\to\cases"
```

To discover cases without processing files:

```bash
python -m revelare.cli.revelare_cli --sync "C:\path\to\cases" --sync-no-process
```

### Programmatic Usage

```python
from revelare.utils.case_sync import CaseSync

# Initialize sync
sync = CaseSync(r"E:\Cases")

# Sync all cases and process new files
stats = sync.sync_all_cases(process_new_files=True)

print(f"Cases created: {stats['cases_created']}")
print(f"Cases updated: {stats['cases_updated']}")
print(f"Files processed: {stats['files_processed']}")
```

## How It Works

1. **Discovery**: Scans `E:\Cases` (or specified directory) for case folders
2. **Comparison**: Compares with existing cases in Project Revelare
3. **Creation**: Creates new cases for folders that don't exist in PR
4. **File Tracking**: Uses file size + modification time to track processed files
5. **Processing**: Processes only new files found in each case
6. **Caching**: Maintains a cache (`.case_sync_cache.json`) to avoid reprocessing

## Configuration

Set environment variables to customize behavior:

- `REVELARE_EXTERNAL_CASES_DIR`: External cases directory (default: `E:\Cases`)
- `REVELARE_SYNC_PROCESS_FILES`: Whether to process files (default: `true`)

## Cache File

The sync maintains a cache file at:
```
cases/.case_sync_cache.json
```

This file tracks which files have been processed to avoid reprocessing. You can delete this file to force a full resync.

## Notes

- Files are tracked by size + modification time (fast, but may miss identical files with different timestamps)
- The sync skips certain directories: `__pycache__`, `.git`, `node_modules`, `temp`, `exports`, `extracted_files`
- New cases are created with minimal metadata (can be updated later via web UI)
- Processing happens incrementally - only new files are processed

