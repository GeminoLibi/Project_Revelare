import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from revelare.core.case_manager import CaseManager
from revelare.config.config import Config
from revelare.utils.logger import get_logger

logger = get_logger("reprocess_cases")

def reprocess_all_cases():
    """Reprocess all existing cases with updated extraction logic"""
    cases_dir = Config.UPLOAD_FOLDER
    case_manager = CaseManager()
    
    if not os.path.exists(cases_dir):
        print(f"Cases directory not found: {cases_dir}")
        return
    
    print(f"Scanning {cases_dir} for cases to reprocess...")
    
    # Find all case directories (those with raw_findings.json or extracted_files)
    cases = []
    for entry in os.listdir(cases_dir):
        entry_path = os.path.join(cases_dir, entry)
        if os.path.isdir(entry_path):
            # Check if it's a processed case
            has_findings = os.path.exists(os.path.join(entry_path, 'raw_findings.json'))
            has_extracted = os.path.exists(os.path.join(entry_path, 'extracted_files'))
            
            if has_findings or has_extracted:
                cases.append(entry)
    
    if not cases:
        print("No cases found to reprocess.")
        return
    
    print(f"Found {len(cases)} cases to reprocess.\n")
    
    processed_count = 0
    failed_count = 0
    
    for i, case_name in enumerate(sorted(cases), 1):
        case_path = os.path.join(cases_dir, case_name)
        print(f"\n[{i}/{len(cases)}] Reprocessing: {case_name}")
        
        # Collect evidence files
        evidence_files = []
        evidence_dir = os.path.join(case_path, 'evidence')
        
        if os.path.exists(evidence_dir):
            # Use evidence directory if it exists
            for root, dirs, files in os.walk(evidence_dir):
                for f in files:
                    file_path = os.path.join(root, f)
                    if os.path.isfile(file_path):
                        evidence_files.append(file_path)
        else:
            # Fall back to extracted_files if evidence doesn't exist
            extracted_dir = os.path.join(case_path, 'extracted_files')
            if os.path.exists(extracted_dir):
                # Get original evidence files if available
                # Otherwise, we'll need to reprocess from extracted files
                print(f"  Note: Using extracted_files directory (evidence not found)")
                # For now, skip cases without evidence - they'd need original files
                if not evidence_files:
                    print(f"  SKIPPED: No evidence files found. Need original evidence to reprocess.")
                    continue
        
        if not evidence_files:
            print(f"  SKIPPED: No evidence files found.")
            continue
        
        print(f"  Found {len(evidence_files)} evidence file(s)")
        
        try:
            # Reprocess the case
            success, message = case_manager.process_evidence_files(case_name, evidence_files)
            
            if success:
                print(f"  SUCCESS: {case_name}")
                print(f"  {message}")
                processed_count += 1
            else:
                print(f"  FAILED: {case_name}")
                print(f"  {message}")
                failed_count += 1
                
        except Exception as e:
            print(f"  ERROR: {case_name}")
            print(f"  {str(e)}")
            import traceback
            traceback.print_exc()
            failed_count += 1
    
    print(f"\n{'='*60}")
    print(f"Reprocessing complete!")
    print(f"  Successfully processed: {processed_count}")
    print(f"  Failed: {failed_count}")
    print(f"  Total: {len(cases)}")
    print(f"{'='*60}")

if __name__ == "__main__":
    reprocess_all_cases()

