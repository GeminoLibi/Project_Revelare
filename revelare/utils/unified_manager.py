#!/usr/bin/env python3
"""
Unified Case Management System
Orchestrates case discovery, synchronization, duplicate detection, and file conversion.
"""
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.utils.case_sync import CaseSync, run_scheduled_sync
from revelare.utils.file_deduplication import (
    find_cross_case_duplicates, format_duplicate_report
)
from revelare.utils.truleo_converter import convert_case_for_truleo

logger = get_logger("unified_manager")


class UnifiedCaseManager:
    """
    Unified manager for case synchronization, duplicate detection, and conversion.
    """
    
    def __init__(self, external_cases_dir: str = r"E:\Cases"):
        """
        Initialize unified manager.
        
        Args:
            external_cases_dir: Path to external cases directory
        """
        self.external_cases_dir = external_cases_dir
        self.case_sync = CaseSync(external_cases_dir)
        self.revelare_cases_dir = Path(Config.UPLOAD_FOLDER)
    
    def run_full_sync(self, process_files: bool = True,
                     check_duplicates: bool = True,
                     check_cross_case_duplicates: bool = True,
                     convert_to_truleo: bool = False,
                     truleo_output_dir: Optional[str] = None) -> Dict[str, any]:
        """
        Run complete synchronization with all features.
        
        Args:
            process_files: Process new files found
            check_duplicates: Check for duplicates before adding files
            check_cross_case_duplicates: Check for duplicates across cases
            convert_to_truleo: Convert files to Truleo format after processing
            truleo_output_dir: Output directory for Truleo conversions
            
        Returns:
            Dictionary with complete statistics
        """
        logger.info("=" * 80)
        logger.info("Starting Unified Case Synchronization")
        logger.info("=" * 80)
        
        results = {
            'sync_stats': {},
            'duplicate_report': None,
            'truleo_conversions': {},
            'errors': []
        }
        
        # Step 1: Synchronize cases
        logger.info("\n[STEP 1] Synchronizing cases...")
        try:
            sync_stats = self.case_sync.sync_all_cases(
                process_new_files=process_files,
                check_duplicates=check_duplicates
            )
            results['sync_stats'] = sync_stats
            
            logger.info(f"Sync complete:")
            logger.info(f"  Cases discovered: {sync_stats.get('cases_discovered', 0)}")
            logger.info(f"  Cases created: {sync_stats.get('cases_created', 0)}")
            logger.info(f"  Cases updated: {sync_stats.get('cases_updated', 0)}")
            logger.info(f"  Files processed: {sync_stats.get('files_processed', 0)}")
            logger.info(f"  Duplicates skipped: {sync_stats.get('duplicates_skipped', 0)}")
            
        except Exception as e:
            error_msg = f"Sync failed: {e}"
            logger.error(error_msg, exc_info=True)
            results['errors'].append(error_msg)
            return results
        
        # Step 2: Check for cross-case duplicates
        if check_cross_case_duplicates:
            logger.info("\n[STEP 2] Checking for cross-case duplicates...")
            try:
                duplicates = find_cross_case_duplicates(self.revelare_cases_dir)
                
                if duplicates:
                    report = format_duplicate_report(duplicates)
                    logger.warning(f"Found {len(duplicates)} duplicate file groups")
                    
                    # Save report
                    report_file = self.revelare_cases_dir / f"duplicate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    with open(report_file, 'w', encoding='utf-8') as f:
                        f.write(f"Duplicate Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("=" * 80 + "\n\n")
                        f.write(report)
                    
                    results['duplicate_report'] = {
                        'file': str(report_file),
                        'duplicate_groups': len(duplicates),
                        'report': report
                    }
                else:
                    logger.info("No cross-case duplicates found")
                    results['duplicate_report'] = {'duplicate_groups': 0}
                    
            except Exception as e:
                error_msg = f"Cross-case duplicate check failed: {e}"
                logger.error(error_msg, exc_info=True)
                results['errors'].append(error_msg)
        
        # Step 3: Convert to Truleo format (if requested)
        if convert_to_truleo:
            logger.info("\n[STEP 3] Converting files to Truleo format...")
            try:
                # Get all cases
                cases = [d.name for d in self.revelare_cases_dir.iterdir() 
                        if d.is_dir() and not d.name.startswith('.')]
                
                truleo_results = {}
                for case_name in cases:
                    logger.info(f"Converting case {case_name}...")
                    try:
                        result = convert_case_for_truleo(
                            case_name,
                            output_dir=truleo_output_dir
                        )
                        truleo_results[case_name] = result
                    except Exception as e:
                        error_msg = f"Truleo conversion failed for {case_name}: {e}"
                        logger.error(error_msg, exc_info=True)
                        truleo_results[case_name] = {'success': False, 'error': error_msg}
                        results['errors'].append(error_msg)
                
                results['truleo_conversions'] = truleo_results
                
                total_converted = sum(r.get('converted', 0) for r in truleo_results.values())
                total_failed = sum(r.get('failed', 0) for r in truleo_results.values())
                logger.info(f"Truleo conversion complete: {total_converted} converted, {total_failed} failed")
                
            except Exception as e:
                error_msg = f"Truleo conversion process failed: {e}"
                logger.error(error_msg, exc_info=True)
                results['errors'].append(error_msg)
        
        logger.info("\n" + "=" * 80)
        logger.info("Unified Synchronization Complete")
        logger.info("=" * 80)
        
        return results
    
    def run_weekly_scan(self) -> Dict[str, any]:
        """
        Run weekly scheduled scan with all checks enabled.
        
        Returns:
            Dictionary with scan results
        """
        return self.run_full_sync(
            process_files=True,
            check_duplicates=True,
            check_cross_case_duplicates=True,
            convert_to_truleo=False  # Can be enabled if needed
        )

