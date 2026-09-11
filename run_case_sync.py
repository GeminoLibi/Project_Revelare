#!/usr/bin/env python3
"""
Manual Case Synchronization Runner
Run this script to manually sync cases from external directory.
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from revelare.utils.unified_manager import UnifiedCaseManager
from revelare.utils.logger import get_logger

logger = get_logger("manual_sync")


def main():
    """Main entry point for manual sync."""
    print("=" * 80)
    print("Project Revelare - Case Synchronization")
    print("=" * 80)
    print()
    
    # Get external cases directory
    if len(sys.argv) > 1:
        external_cases_dir = sys.argv[1]
    else:
        default_dir = r"E:\Cases"
        external_cases_dir = input(f"Enter external cases directory [{default_dir}]: ").strip()
        if not external_cases_dir:
            external_cases_dir = default_dir
    
    # Check if directory exists
    if not os.path.exists(external_cases_dir):
        print(f"Error: Directory not found: {external_cases_dir}")
        return 1
    
    # Ask if should process files
    process_files_input = input("Process new files found? [Y/n]: ").strip().lower()
    process_files = process_files_input != 'n'
    
    print()
    print(f"External cases directory: {external_cases_dir}")
    print(f"Process new files: {process_files}")
    print()
    print("Starting synchronization...")
    print()
    
    # Use unified manager
    manager = UnifiedCaseManager(external_cases_dir)
    results = manager.run_full_sync(
        process_files=process_files,
        check_duplicates=True,
        check_cross_case_duplicates=True,
        convert_to_truleo=False
    )
    
    stats = results.get('sync_stats', {})
    
    if results:
        print()
        print("=" * 80)
        print("Synchronization Complete!")
        print("=" * 80)
        print(f"Cases discovered: {stats.get('cases_discovered', 0)}")
        print(f"Cases created: {stats.get('cases_created', 0)}")
        print(f"Cases updated: {stats.get('cases_updated', 0)}")
        print(f"Files processed: {stats.get('files_processed', 0)}")
        print(f"Duplicates skipped: {stats.get('duplicates_skipped', 0)}")
        
        if results.get('duplicate_report'):
            dup_info = results['duplicate_report']
            if dup_info.get('duplicate_groups', 0) > 0:
                print(f"\nCross-case duplicates found: {dup_info['duplicate_groups']} groups")
                print(f"Report saved to: {dup_info.get('file', 'N/A')}")
        
        if results.get('errors') or stats.get('errors'):
            all_errors = results.get('errors', []) + stats.get('errors', [])
            print(f"\nErrors encountered: {len(all_errors)}")
            for error in all_errors[:10]:  # Show first 10 errors
                print(f"  - {error}")
            if len(all_errors) > 10:
                print(f"  ... and {len(all_errors) - 10} more errors")
        print("=" * 80)
        return 0
    else:
        print("Synchronization failed!")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nSynchronization interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

