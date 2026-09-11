#!/usr/bin/env python3
"""
Scheduled Case Synchronization Runner
Can be run manually or scheduled via Windows Task Scheduler.
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from revelare.utils.unified_manager import UnifiedCaseManager
from revelare.utils.logger import get_logger

logger = get_logger("scheduled_sync")


def main():
    """Main entry point for scheduled sync."""
    # Default external cases directory
    external_cases_dir = os.environ.get('REVELARE_EXTERNAL_CASES_DIR', r"E:\Cases")
    
    # Check if we should process files (default: yes)
    process_files = os.environ.get('REVELARE_SYNC_PROCESS_FILES', 'true').lower() == 'true'
    
    logger.info("Starting scheduled case synchronization...")
    logger.info(f"External cases directory: {external_cases_dir}")
    logger.info(f"Process new files: {process_files}")
    
    # Use unified manager for weekly scan
    manager = UnifiedCaseManager(external_cases_dir)
    results = manager.run_weekly_scan()
    
    if results and not results.get('errors'):
        logger.info("Scheduled sync completed successfully")
        return 0
    else:
        logger.error(f"Scheduled sync completed with errors: {results.get('errors', [])}")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.warning("Sync interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

