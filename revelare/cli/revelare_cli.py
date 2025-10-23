import os
import sys
import argparse
import tempfile
import shutil
import json
import csv
import re
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path
from datetime import datetime

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator
from revelare.core.extractor import run_extraction
from revelare.utils import reporter
import revelare.utils.file_extractor as file_extractor
from revelare.core.case_manager import case_manager

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8') 

logger = get_logger(__name__)
cli_logger = RevelareLogger.get_logger('cli')

def _configure_logging_level(args):
    log_level = 'DEBUG' if args.debug else ('INFO' if args.verbose else Config.LOG_LEVEL)
    logging.getLogger('revelare').setLevel(getattr(logging, log_level.upper()))

def validate_input_files(file_paths: List[str]) -> Tuple[List[str], int]:
    valid_files = []
    total_size = 0
    
    for file_path in file_paths:
        try:
            if not os.path.exists(file_path):
                cli_logger.warning(f"File not found: {file_path}")
                continue
            
            valid_files.append(file_path)
            total_size += os.path.getsize(file_path)
            
        except Exception as e:
            cli_logger.error(f"Error validating file {file_path}: {e}")
            continue
    
    return valid_files, total_size

def _export_results(project_dir: str, findings: Dict, project_name: str):
    enhanced_findings = {k: v for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict)}
         
    json_path = os.path.join(project_dir, "indicators.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(enhanced_findings, f, indent=2, ensure_ascii=False)
    print(f"[OK] JSON export saved: {os.path.basename(json_path)}")
    
    csv_path = os.path.join(project_dir, "indicators.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Indicator', 'Context'])
        for category, items in enhanced_findings.items():
            if items:
                for indicator, context in items.items():
                    safe_context = str(context).replace('\n', ' ')[:250] 
                    writer.writerow([category, indicator, safe_context])
    print(f"[OK] CSV export saved: {os.path.basename(csv_path)}")

def process_project(project_name: str, input_files: List[str], output_dir: str, args) -> bool:
    is_name_valid, error_msg = SecurityValidator.validate_project_name(project_name)
    if not is_name_valid:
        cli_logger.critical(f"Invalid project name: {error_msg}")
        return False
        
    project_dir = os.path.abspath(os.path.join(output_dir, project_name))
    Path(project_dir).mkdir(parents=True, exist_ok=True)
    
    temp_working_dir = Path(tempfile.mkdtemp(prefix=f"revelare_{project_name}_temp_"))
    
    print(f"\n[START] Starting Project: {project_name}")
    
    try:
        print(f"\n[INGEST] Staging and extracting archives...")
        
        for i, file_path in enumerate(input_files, 1):
            file_name = os.path.basename(file_path)
            temp_copy_path = temp_working_dir / file_name
            shutil.copy2(file_path, temp_copy_path)
            if file_name.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                print(f"  [{i}/{len(input_files)}] Extracting: {file_name}")
                file_extractor.safe_extract_archive(str(temp_copy_path), str(temp_working_dir))
            
        all_extracted_paths = [str(p) for p in temp_working_dir.rglob('*') if p.is_file()]
        
        print(f"\n[EXTRACT] Running indicator extraction on {len(all_extracted_paths)} files...")
        
        original_cwd = os.getcwd()
        os.chdir(temp_working_dir)
        try:
            findings = run_extraction(all_extracted_paths)
        finally:
            os.chdir(original_cwd)
        
        total_findings = sum(len(items) for k, items in findings.items() if k != 'Processing_Summary')
        print(f"[OK] Found {total_findings} indicators.")

        report_generator = reporter.ReportGenerator()
        ip_addresses = [v for k in findings if 'IPv4' in k for v in findings[k].keys()]
        enriched_ips = report_generator.enrich_ips(ip_addresses)
        
        report_path = os.path.join(project_dir, f"{project_name}_report.html")
        report_html = report_generator.generate_report(project_name, findings, enriched_ips)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        print(f"[OK] Report generated: {os.path.basename(report_path)}")
        
        _export_results(project_dir, findings, project_name)
        
        print(f"\n[SUCCESS] Project '{project_name}' completed successfully!")
        print(f"[INFO] Outputs saved to: {project_dir}")
        return True
        
    except Exception as e:
        cli_logger.error(f"CLI project processing failed: {e}", exc_info=True)
        print(f"[ERROR] Critical processing failure. Check logs for details.")
        return False
        
    finally:
        file_extractor.cleanup_temp_files(str(temp_working_dir))
        print(f"[CLEANUP] Temporary directory purged.")

def main():
    parser = argparse.ArgumentParser(description="Project Revelare CLI")
    
    parser.add_argument('-p', '--project', help='Project name')
    parser.add_argument('-f', '--files', nargs='+', help='Input files to process')
    parser.add_argument('-o', '--output', default='cases', help='Output directory (default: cases)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    
    parser.add_argument('--onboard', action='store_true', help='Run interactive case onboarding wizard.')
    parser.add_argument('--add-files', help='Add files to an existing case (specify case name)')
    parser.add_argument('--enhanced', action='store_true', help='Launch enhanced CLI with full GUI functionality')
    
    args = parser.parse_args()
    
    _configure_logging_level(args)
    
    print("Project Revelare CLI v2.5")
    print("=" * 50)

    if args.enhanced:
        print("\nLaunching Enhanced CLI Interface...")
        try:
            from revelare.cli.enhanced_cli import EnhancedCLI
            cli = EnhancedCLI()
            cli.run()
        except ImportError as e:
            print(f"Error launching enhanced CLI: {e}")
            return 1
        return 0

    if args.onboard:
        print("\n" + "="*60 + "\nProject Revelare - Case Onboarding & Creation\n" + "="*60)
        investigator_info = case_manager.onboard.get_investigator_info()
        agency_info = case_manager.onboard.get_agency_info()
        case_info = case_manager.onboard.get_case_info()
        classification_info = case_manager.onboard.get_classification_info()

        success, message, project_dir = case_manager.create_case_via_onboarding(
            case_info["case_number"], case_info["incident_type"],
            investigator_info, agency_info, classification_info
        )

        if success:
            print(f"\n[OK] {message}\nProject directory: {project_dir}")
            evidence_files = case_manager.onboard.get_evidence_files(project_dir)
            if evidence_files:
                project_name = os.path.basename(project_dir)
                print(f"\nProcessing evidence files...")
                success, process_msg = case_manager.process_evidence_files(project_name, evidence_files)
                if success: print(f"[OK] {process_msg}")
                else: print(f"[ERROR] {process_msg}")
            else:
                print("[INFO] No evidence files added.")
        else:
            print(f"[ERROR] {message}")
            sys.exit(1)
        return 0

    if args.add_files:
        case_name = args.add_files
        files = args.files
        if not files:
            print("[ERROR] Must specify --files when using --add-files")
            return 1

        print(f"\nAdding {len(files)} files to case '{case_name}'")
        valid_files, _ = validate_input_files(files)
        if not valid_files:
            print("[ERROR] No valid files found")
            return 1
        
        success, message = case_manager.process_evidence_files(case_name, valid_files)
        if success: print(f"[OK] {message}")
        else: print(f"[ERROR] {message}"); return 1
        return 0

    if not args.project or not args.files:
        parser.print_help()
        print("\n[ERROR] Must specify --project and --files (or use --onboard)")
        return 1
        
    print(f"\n[VALIDATE] Validating input files...")
    valid_files, _ = validate_input_files(args.files)
    if not valid_files:
        print("[ERROR] No valid files to process. Aborting.")
        return 1
    
    success = process_project(args.project, valid_files, args.output, args)
    return 0 if success else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n[INTERRUPT] Interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        logging.getLogger('cli').critical(f"CLI unexpected error: {e}", exc_info=True)
        print(f"\n[ERROR] Unexpected error. Check logs for details.")
        sys.exit(1)