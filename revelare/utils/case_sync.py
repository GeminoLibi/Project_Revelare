#!/usr/bin/env python3
"""
Case Synchronization Module
Scans external case directories, creates missing cases, and processes new files.
Can be run manually or scheduled.
"""
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from revelare.config.config import Config
from revelare.core.case_manager import CaseManager
from revelare.utils.logger import get_logger
from revelare.utils.file_deduplication import (
    check_duplicate_in_revelare, build_quick_hash_index,
    find_cross_case_duplicates, format_duplicate_report
)

logger = get_logger("case_sync")


class CaseSync:
    """Synchronizes external case directories with Project Revelare."""
    
    def __init__(self, external_cases_dir: str):
        """
        Initialize CaseSync.
        
        Args:
            external_cases_dir: Path to external cases directory (e.g., E:\\Cases)
        """
        self.external_cases_dir = Path(external_cases_dir)
        self.case_manager = CaseManager()
        self.revelare_cases_dir = Path(Config.UPLOAD_FOLDER)
        
        # Track processed files to avoid reprocessing
        self.processed_files_cache_file = self.revelare_cases_dir / ".case_sync_cache.json"
        self.processed_files_cache = self._load_cache()
        
        # Quick hash index for duplicate detection (built on demand)
        self._quick_hash_index = None
        
    def _load_cache(self) -> Dict[str, Set[str]]:
        """Load cache of processed files."""
        if self.processed_files_cache_file.exists():
            try:
                with open(self.processed_files_cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Convert lists back to sets
                    return {case: set(files) for case, files in data.items()}
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
        return {}
    
    def _save_cache(self):
        """Save cache of processed files."""
        try:
            # Convert sets to lists for JSON serialization
            data = {case: list(files) for case, files in self.processed_files_cache.items()}
            with open(self.processed_files_cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Get hash of file for tracking."""
        try:
            stat = file_path.stat()
            # Use size + mtime as a quick hash (faster than MD5 for large files)
            return f"{stat.st_size}_{stat.st_mtime}"
        except Exception:
            return ""
    
    def _get_existing_cases(self) -> Set[str]:
        """Get set of existing case names in Project Revelare."""
        if not self.revelare_cases_dir.exists():
            return set()
        
        cases = set()
        for item in self.revelare_cases_dir.iterdir():
            if item.is_dir() and not item.name.startswith('.'):
                cases.add(item.name)
        return cases
    
    def _discover_external_cases(self) -> List[Tuple[Path, str]]:
        """
        Discover case directories in external location.
        Handles nested structure where cases may be in subdirectories (category/case structure).
        
        Returns:
            List of tuples: (case_path, case_name)
        """
        if not self.external_cases_dir.exists():
            logger.error(f"External cases directory not found: {self.external_cases_dir}")
            return []
        
        cases = []
        root_items = list(self.external_cases_dir.iterdir())
        
        # Check if root items look like categories (contain subdirectories that look like case IDs)
        # Case IDs are typically numeric (e.g., 2510013703, 2509034425)
        looks_like_categories = False
        for item in root_items[:5]:  # Sample first 5
            if item.is_dir() and not item.name.startswith('.'):
                try:
                    subdirs = [d for d in item.iterdir() if d.is_dir() and not d.name.startswith('.')]
                    # Check if subdirectories look like case IDs (mostly numeric)
                    numeric_subdirs = [d for d in subdirs if d.name.replace('_', '').replace('-', '').isdigit()]
                    # If most subdirectories are numeric IDs, this is likely a category folder
                    if len(subdirs) > 0 and len(numeric_subdirs) >= len(subdirs) * 0.7:  # 70% are numeric
                        looks_like_categories = True
                        break
                except Exception:
                    continue
        
        if looks_like_categories:
            logger.info("Detected category/case structure, scanning nested directories...")
            # Nested structure: category/case
            for category_dir in self.external_cases_dir.iterdir():
                if not category_dir.is_dir() or category_dir.name.startswith('.'):
                    continue
                
                # Check subdirectories in this category
                for case_dir in category_dir.iterdir():
                    if case_dir.is_dir() and not case_dir.name.startswith('.'):
                        # Check if it has content (files or meaningful subdirectories)
                        has_content = False
                        try:
                            for subitem in case_dir.iterdir():
                                if subitem.is_file() or (subitem.is_dir() and not subitem.name.startswith('.')):
                                    has_content = True
                                    break
                        except Exception:
                            continue
                        
                        if has_content:
                            # Use case number/ID as name
                            case_name = case_dir.name
                            cases.append((case_dir, case_name))
        else:
            logger.info("Detected flat structure, scanning root directories...")
            # Flat structure: cases directly in root
            for item in self.external_cases_dir.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    # Check if it has content
                    has_content = False
                    try:
                        for subitem in item.iterdir():
                            if subitem.is_file() or (subitem.is_dir() and not subitem.name.startswith('.')):
                                has_content = True
                                break
                    except Exception:
                        continue
                    
                    if has_content:
                        cases.append((item, item.name))
        
        logger.info(f"Discovered {len(cases)} cases in {self.external_cases_dir}")
        return cases
    
    def _create_case_from_directory(self, case_dir: Path) -> Tuple[bool, Optional[str]]:
        """
        Create a new case in Project Revelare from an external directory.
        
        Args:
            case_dir: Path to external case directory
            
        Returns:
            Tuple of (success, case_name)
        """
        case_name = case_dir.name
        
        # Validate case name
        is_valid, error_msg = self.case_manager.validate_case_name(case_name)
        if not is_valid:
            logger.warning(f"Invalid case name {case_name}: {error_msg}")
            return False, None
        
        # Create case with minimal metadata - use case name directly (no suffix)
        try:
            # Create project directory directly with just the case name (bypass onboarding's naming)
            project_dir = os.path.join(Config.UPLOAD_FOLDER, case_name)
            
            # Skip if already exists
            if os.path.exists(project_dir):
                logger.debug(f"Case directory already exists: {case_name}")
                return True, case_name
            
            # Create directory structure directly
            Path(project_dir).mkdir(parents=True, exist_ok=True)
            subdirs = ["evidence", "analysis", "reports", "exports", "logs"]
            for subdir in subdirs:
                Path(os.path.join(project_dir, subdir)).mkdir(exist_ok=True)
            
            # Create case metadata
            from revelare.core.case_taxonomy import (
                infer_incident_type_from_text,
                infer_tags_from_text,
                parse_tags_input,
            )

            parent_tag_source = case_dir.parent.name if case_dir.parent != self.external_cases_dir else ""
            inferred_tags = infer_tags_from_text(case_name, [parent_tag_source])
            inferred_incident = infer_incident_type_from_text(
                f"{case_name} {parent_tag_source}"
            ) or "Unknown"

            case_info = {
                "case_number": case_name,
                "incident_type": inferred_incident,
                "tags": parse_tags_input(inferred_tags),
                "description": f"Auto-imported from {self.external_cases_dir}",
                "incident_date": datetime.now().strftime('%Y-%m-%d'),
                "created_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Save minimal metadata
            self.case_manager.onboard.save_case_metadata(
                project_dir,
                investigator_info={"name": "Auto-Import", "email": "", "badge": ""},
                agency_info={"name": "Auto-Import", "unit": ""},
                case_info=case_info,
                classification_info={"level": "Unclassified"}
            )
            
            logger.info(f"Created new case: {case_name}")
            return True, case_name
            
        except Exception as e:
            logger.error(f"Failed to create case {case_name}: {e}", exc_info=True)
            return False, None
    
    def _find_new_files(self, case_name: str, external_case_dir: Path, 
                        check_duplicates: bool = True) -> Tuple[List[Path], List[Dict[str, str]]]:
        """
        Find new files in external case directory that haven't been processed.
        Also checks for duplicates in Revelare.
        
        Args:
            case_name: Name of the case
            external_case_dir: Path to external case directory
            check_duplicates: If True, check for duplicates in Revelare
            
        Returns:
            Tuple of (new_file_paths, duplicate_info_list)
        """
        processed_files = self.processed_files_cache.get(case_name, set())
        new_files = []
        duplicates_found = []
        
        # Build quick hash index if checking duplicates
        if check_duplicates and self._quick_hash_index is None:
            logger.info("Building quick hash index for duplicate detection...")
            self._quick_hash_index = build_quick_hash_index(self.revelare_cases_dir)
        
        # Walk through external case directory
        for root, dirs, files in os.walk(external_case_dir):
            # Skip certain directories
            skip_dirs = {'__pycache__', '.git', 'node_modules', 'temp', 'exports', 'extracted_files'}
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if file.startswith('.'):
                    continue
                
                file_path = Path(root) / file
                file_hash = self._get_file_hash(file_path)
                
                # Check if file has been processed
                if file_hash not in processed_files:
                    # Check for duplicates in Revelare
                    if check_duplicates:
                        is_dup, dup_case, dup_path = check_duplicate_in_revelare(
                            file_path, self.revelare_cases_dir, self._quick_hash_index
                        )
                        if is_dup:
                            duplicates_found.append({
                                'file': str(file_path),
                                'duplicate_case': dup_case,
                                'duplicate_path': dup_path
                            })
                            logger.debug(f"Duplicate detected: {file_path.name} already exists in case {dup_case}")
                            continue  # Skip duplicate files
                    
                    new_files.append(file_path)
        
        if duplicates_found:
            logger.info(f"Found {len(duplicates_found)} duplicate files in case {case_name} (skipped)")
        
        logger.info(f"Found {len(new_files)} new files in case {case_name}")
        return new_files, duplicates_found
    
    def _mark_files_processed(self, case_name: str, files: List[Path]):
        """Mark files as processed in cache."""
        if case_name not in self.processed_files_cache:
            self.processed_files_cache[case_name] = set()
        
        for file_path in files:
            file_hash = self._get_file_hash(file_path)
            self.processed_files_cache[case_name].add(file_hash)
    
    def sync_all_cases(self, process_new_files: bool = True, 
                       check_duplicates: bool = True) -> Dict[str, any]:
        """
        Synchronize all cases from external directory.
        
        Args:
            process_new_files: If True, process new files found in existing cases
            check_duplicates: If True, check for duplicates before adding files
            
        Returns:
            Dictionary with sync statistics
        """
        stats = {
            'cases_discovered': 0,
            'cases_created': 0,
            'cases_updated': 0,
            'files_processed': 0,
            'duplicates_skipped': 0,
            'errors': []
        }
        
        logger.info(f"Starting case synchronization from {self.external_cases_dir}")
        
        # Get existing cases
        existing_cases = self._get_existing_cases()
        logger.info(f"Found {len(existing_cases)} existing cases in Project Revelare")
        
        # Discover external cases
        external_cases = self._discover_external_cases()
        stats['cases_discovered'] = len(external_cases)
        
        # Process each external case
        for external_case_dir, case_name in external_cases:
            
            try:
                if case_name not in existing_cases:
                    # Create new case
                    success, created_case_name = self._create_case_from_directory(external_case_dir)
                    if success:
                        stats['cases_created'] += 1
                        existing_cases.add(case_name)  # Add to set so we can process files
                    else:
                        stats['errors'].append(f"Failed to create case {case_name}")
                        continue
                
                # Find and process new files
                if process_new_files:
                    new_files, duplicates = self._find_new_files(
                        case_name, external_case_dir, check_duplicates=check_duplicates
                    )
                    
                    stats['duplicates_skipped'] += len(duplicates)
                    
                    if new_files:
                        logger.info(f"Processing {len(new_files)} new files for case {case_name}")
                        
                        # Convert Path objects to strings for process_evidence_files
                        file_paths = [str(f) for f in new_files]
                        
                        # Process files
                        success, message = self.case_manager.process_evidence_files(
                            case_name,
                            file_paths
                        )
                        
                        if success:
                            stats['files_processed'] += len(new_files)
                            stats['cases_updated'] += 1
                            self._mark_files_processed(case_name, new_files)
                            logger.info(f"Successfully processed {len(new_files)} files for {case_name}")
                        else:
                            stats['errors'].append(f"Failed to process files for {case_name}: {message}")
                
            except Exception as e:
                error_msg = f"Error processing case {case_name}: {e}"
                logger.error(error_msg, exc_info=True)
                stats['errors'].append(error_msg)
        
        # Save cache
        self._save_cache()
        
        logger.info(f"Sync complete: {stats}")
        return stats


def run_scheduled_sync(external_cases_dir: str = r"E:\Cases", process_files: bool = True,
                       check_duplicates: bool = True, check_cross_case_duplicates: bool = True):
    """
    Run scheduled case synchronization with duplicate detection.
    
    Args:
        external_cases_dir: Path to external cases directory
        process_files: Whether to process new files found
        check_duplicates: If True, check for duplicates before adding files
        check_cross_case_duplicates: If True, check for duplicates across cases after sync
    """
    try:
        sync = CaseSync(external_cases_dir)
        stats = sync.sync_all_cases(
            process_new_files=process_files,
            check_duplicates=check_duplicates
        )
        
        # Check for cross-case duplicates
        if check_cross_case_duplicates:
            logger.info("Checking for cross-case duplicates...")
            try:
                duplicates = find_cross_case_duplicates(sync.revelare_cases_dir)
                if duplicates:
                    report = format_duplicate_report(duplicates)
                    logger.warning(f"Cross-case duplicates found:\n{report}")
                    
                    # Save report to file
                    report_file = sync.revelare_cases_dir / f"duplicate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(report_file, 'w', encoding='utf-8') as f:
                        f.write(f"Duplicate Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("=" * 80 + "\n\n")
                        f.write(report)
                    
                    stats['cross_case_duplicates'] = len(duplicates)
                    stats['duplicate_report_file'] = str(report_file)
                else:
                    logger.info("No cross-case duplicates found")
                    stats['cross_case_duplicates'] = 0
            except Exception as e:
                logger.error(f"Error checking cross-case duplicates: {e}", exc_info=True)
                stats['errors'].append(f"Cross-case duplicate check failed: {e}")
        
        logger.info("=" * 60)
        logger.info("Case Synchronization Complete")
        logger.info("=" * 60)
        logger.info(f"Cases discovered: {stats['cases_discovered']}")
        logger.info(f"Cases created: {stats['cases_created']}")
        logger.info(f"Cases updated: {stats['cases_updated']}")
        logger.info(f"Files processed: {stats['files_processed']}")
        logger.info(f"Duplicates skipped: {stats.get('duplicates_skipped', 0)}")
        if stats.get('cross_case_duplicates', 0) > 0:
            logger.warning(f"Cross-case duplicates found: {stats['cross_case_duplicates']}")
            logger.info(f"Report saved to: {stats.get('duplicate_report_file', 'N/A')}")
        if stats['errors']:
            logger.warning(f"Errors encountered: {len(stats['errors'])}")
            for error in stats['errors']:
                logger.warning(f"  - {error}")
        logger.info("=" * 60)
        
        return stats
        
    except Exception as e:
        logger.error(f"Fatal error during sync: {e}", exc_info=True)
        return None


if __name__ == "__main__":
    import sys
    
    # Allow command line argument for external directory
    external_dir = sys.argv[1] if len(sys.argv) > 1 else r"E:\Cases"
    process_files = sys.argv[2].lower() != 'false' if len(sys.argv) > 2 else True
    
    run_scheduled_sync(external_dir, process_files)

