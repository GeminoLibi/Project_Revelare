#!/usr/bin/env python
"""
Clean all existing cases using updated regex patterns.
This re-validates findings and removes false positives without reprocessing files.
"""
import os
import sys
from pathlib import Path
from revelare.core.case_manager import CaseManager
from revelare.utils.logger import get_logger
from revelare.config.config import Config

logger = get_logger("case_cleaner")

# Assuming the script is run from the project root
PROJECT_ROOT = Path(__file__).resolve().parent
CASES_DIR = Path(Config.UPLOAD_FOLDER)

def clean_all_cases():
    """Clean all cases using updated regex patterns"""
    if not CASES_DIR.exists():
        logger.error(f"Cases directory not found: {CASES_DIR}")
        return
    
    logger.info(f"Scanning {CASES_DIR} for cases to clean...")
    
    case_manager = CaseManager()
    cleaned_count = 0
    total_removed = 0
    
    # Get all case directories
    case_dirs = [d for d in CASES_DIR.iterdir() if d.is_dir()]
    
    if not case_dirs:
        logger.warning("No cases found to clean.")
        return
    
    logger.info(f"Found {len(case_dirs)} cases to clean\n")
    
    for case_entry in sorted(case_dirs):
        project_name = case_entry.name
        raw_findings_path = case_entry / 'raw_findings.json'
        
        if not raw_findings_path.exists():
            logger.warning(f"Skipping {project_name}: raw_findings.json not found. Case might not have been processed yet.")
            continue
        
        logger.info(f"[{cleaned_count+1}/{len(case_dirs)}] Cleaning Case: {project_name}")
        
        try:
            logger.info(f"  Loading findings...")
            success, message, stats = case_manager.clean_findings_regex(project_name)
            
            if success:
                removed = stats.get('total_removed', 0)
                total_removed += removed
                logger.info(f"  ✓ SUCCESS: {message}")
                if removed > 0:
                    logger.info(f"  Removed {removed} false positives")
                    # Log breakdown by category
                    for category, count in stats.get('removed', {}).items():
                        if count > 0:
                            logger.info(f"    - {category}: {removed} removed")
                else:
                    logger.info(f"  No false positives found (all findings valid)")
                cleaned_count += 1
            else:
                logger.error(f"  ✗ FAILURE: {message}")
                
        except Exception as e:
            logger.error(f"  ✗ ERROR cleaning {project_name}: {e}", exc_info=True)
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Cleaning complete!")
    logger.info(f"  Cases cleaned: {cleaned_count}/{len(case_dirs)}")
    logger.info(f"  Total false positives removed: {total_removed}")
    logger.info(f"{'='*60}")

if __name__ == "__main__":
    try:
        clean_all_cases()
    except KeyboardInterrupt:
        logger.warning("\nCleaning interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

