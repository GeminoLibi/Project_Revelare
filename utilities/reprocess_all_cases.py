import os
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    
    # Find all case directories (findings, ingest manifest, or legacy vault copies)
    cases = []
    for entry in os.listdir(cases_dir):
        entry_path = os.path.join(cases_dir, entry)
        if os.path.isdir(entry_path):
            has_findings = os.path.exists(os.path.join(entry_path, 'raw_findings.json'))
            has_extracted = os.path.exists(os.path.join(entry_path, 'extracted_files'))
            has_manifest = os.path.exists(os.path.join(entry_path, 'ingest_manifest.json'))
            
            if has_findings or has_extracted or has_manifest:
                cases.append(entry)
    
    if not cases:
        print("No cases found to reprocess.")
        return
    
    print(f"Found {len(cases)} cases to reprocess.\n")
    
    processed_count = 0
    failed_count = 0
    
    for i, case_name in enumerate(sorted(cases), 1):
        print(f"\n[{i}/{len(cases)}] Reprocessing: {case_name}")
        
        evidence_files = case_manager.get_evidence_files_for_case(case_name)
        
        if not evidence_files:
            print(f"  SKIPPED: No source files found (legacy vault empty and original SourcePath missing).")
            continue
        
        print(f"  Found {len(evidence_files)} source file(s)")
        
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

