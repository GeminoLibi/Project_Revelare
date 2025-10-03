#!/usr/bin/env python3
"""
Project Revelare CLI - Command Line Interface
"""

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
from config import Config
from logger import get_logger, RevelareLogger
from security import SecurityValidator
import extractor
import reporter
import file_extractor
from revelare_onboard import RevelareOnboard

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8') 

logger = get_logger(__name__)
cli_logger = RevelareLogger.get_logger('cli')

def _configure_logging_level(args):
    log_level = 'DEBUG' if args.debug else ('INFO' if args.verbose else Config.LOG_LEVEL)
    logging.getLogger('revelare').setLevel(getattr(logging, log_level.upper()))
    cli_logger.info(f"Log level set to: {log_level}")

def validate_input_files(file_paths: List[str]) -> Tuple[List[str], int]:
    valid_files = []
    total_size = 0
    
    for file_path in file_paths:
        try:
            if not os.path.exists(file_path):
                cli_logger.warning(f"File not found: {file_path}")
                continue
                
            if not os.access(file_path, os.R_OK):
                cli_logger.warning(f"File not readable: {file_path}")
                continue
                
            file_size = os.path.getsize(file_path)
            if file_size > Config.MAX_CONTENT_LENGTH:
                cli_logger.warning(f"File too large: {file_path} ({file_size} bytes)")
                continue
                
            if not SecurityValidator.is_safe_path(file_path):
                cli_logger.warning(f"Unsafe file path: {file_path}")
                continue
                
            valid_files.append(file_path)
            total_size += file_size
            cli_logger.info(f"Valid file: {file_path} ({file_size} bytes)")
            
        except Exception as e:
            cli_logger.error(f"Error validating file {file_path}: {e}")
            continue
    
    cli_logger.info(f"Validation complete: {len(valid_files)} valid files, {total_size} total bytes")
    return valid_files, total_size

def _export_results(project_dir: str, findings: Dict, project_name: str):
    enhanced_findings = {k: v for k, v in findings.items() if k != 'Processing_Summary' and isinstance(v, dict)}
         
    json_path = os.path.join(project_dir, "indicators.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(enhanced_findings, f, indent=2, ensure_ascii=False)
    cli_logger.info(f"JSON export saved: {json_path}")
    print(f"[OK] [OK] JSON export: {os.path.basename(json_path)}")
    
    csv_path = os.path.join(project_dir, "indicators.csv")
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Indicator', 'Context'])
        for category, items in enhanced_findings.items():
            if items:
                for indicator, context in items.items():
                    if isinstance(context, dict):
                        safe_context = str(context)[:250]
                    else:
                        safe_context = str(context).replace('\n', ' ')[:250] 
                    writer.writerow([category, indicator, safe_context])
    cli_logger.info(f"CSV export saved: {csv_path}")
    print(f"[OK] [OK] CSV export: {os.path.basename(csv_path)}")

def process_project(project_name: str, input_files: List[str], output_dir: str) -> bool:
    is_name_valid, error_msg = SecurityValidator.validate_project_name(project_name)
    if not is_name_valid:
        cli_logger.critical(f"Invalid project name: {error_msg}")
        return False
        
    safe_project_name = project_name
    
    project_dir = os.path.abspath(os.path.join(output_dir, safe_project_name))
    Path(project_dir).mkdir(parents=True, exist_ok=True)
    
    temp_working_dir = Path(tempfile.mkdtemp(prefix=f"revelare_{safe_project_name}_temp_"))
    extracted_files_dir = Path(project_dir) / "extracted_files"
    extracted_files_dir.mkdir(exist_ok=True)
    
    cli_logger.info(f"Starting Project: {safe_project_name}. Temp dir: {temp_working_dir.name}")
    print(f"\n[START] Starting Project: {safe_project_name}")
    
    try:
        print(f"\n[INGEST] Staging and extracting archives to temp working directory...")
        
        for i, file_path in enumerate(input_files, 1):
            file_name = os.path.basename(file_path)
            temp_copy_path = temp_working_dir / file_name
            
            shutil.copy2(file_path, temp_copy_path)
            
            if file_name.lower().endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
                print(f"  [{i}/{len(input_files)}] Extracting archive: {file_name}")
                file_extractor.safe_extract_archive(str(temp_copy_path), str(temp_working_dir))
            
        all_extracted_paths = [str(p) for p in temp_working_dir.rglob('*') if p.is_file()]
        
        print(f"\n[EXTRACT] Running indicator extraction on {len(all_extracted_paths)} files...")
        
        original_cwd = os.getcwd()
        os.chdir(temp_working_dir)
        try:
            findings = extractor.run_extraction(all_extracted_paths)
        finally:
            os.chdir(original_cwd)
        
        total_findings = sum(len(items) for k, items in findings.items() if k != 'Processing_Summary')
        print(f"[OK] [OK] Found {total_findings} indicators.")

        print(f"\n[ORGANIZE] Organizing files and renaming...")
        
        file_mapping = file_extractor.extract_and_rename_files(
             str(temp_working_dir),
             safe_project_name, 
             str(extracted_files_dir)
        )
        print(f"[OK] [OK] {len(file_mapping)} files moved to {extracted_files_dir.name} and renamed.")

        report_generator = reporter.ReportGenerator()
        ip_addresses = [v for k in findings if 'IPv4' in k for v in findings[k].keys()]
        enriched_ips = report_generator.enrich_ips(ip_addresses)
        
        report_path = os.path.join(project_dir, f"{safe_project_name}_report.html")
        report_html = report_generator.generate_report(safe_project_name, findings, enriched_ips)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        print(f"[OK] [OK] Report generated: {os.path.basename(report_path)}")
        
        _export_results(project_dir, findings, safe_project_name)
        
        print(f"\n[SUCCESS] Project '{project_name}' completed successfully!")
        print(f"[INFO] All outputs saved to: {project_dir}")
        
        return True
        
    except Exception as e:
        cli_logger.error(f"CLI project processing failed: {e}", exc_info=True)
        print(f"[ERROR] [ERROR] Critical processing failure. Check logs for details.")
        return False
        
    finally:
        file_extractor.cleanup_temp_files(str(temp_working_dir))
        print(f"[CLEANUP] [CLEANUP] Temporary directory purged: {temp_working_dir.name}")


def main():
    
    parser = argparse.ArgumentParser(
        description="Project Revelare CLI - Enhanced Data Extraction Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process a single file
  python revelare_cli.py -p "case_001" -f evidence.zip
  
  # Run interactive onboarding wizard
  python revelare_cli.py --onboard
        """
    )
    
    parser.add_argument('-p', '--project', help='Project name')
    parser.add_argument('-f', '--files', nargs='+', help='Input files to process')
    parser.add_argument('-o', '--output', default='output', help='Output directory (default: output)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging (INFO)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging (DEBUG with full tracebacks)')
    parser.add_argument('--max-size', type=int, help=f'Max file size in MB (default: {Config.MAX_CONTENT_LENGTH // (1024*1024)})')
    
    parser.add_argument('--onboard', action='store_true', help='Run interactive case onboarding wizard (collects metadata).')
    
    args = parser.parse_args()
    
    if args.max_size:
        Config.MAX_CONTENT_LENGTH = args.max_size * 1024 * 1024
        cli_logger.info(f"Max file size overridden to: {args.max_size}MB")
        print(f"[CONFIG] Max file size set to: {args.max_size}MB")
    
    _configure_logging_level(args)
    
    print("Project Revelare CLI v2.2 (Unified Maestro)")
    print("=" * 50)

    if args.onboard:
        onboard = RevelareOnboard()
        onboard.display_header()
        
        investigator_info = onboard.get_investigator_info()
        agency_info = onboard.get_agency_info()
        case_info = onboard.get_case_info()
        classification_info = onboard.get_classification_info()
        
        project_dir = onboard.create_project_structure(case_info)
        project_name = os.path.basename(project_dir)
        
        onboard.save_case_metadata(project_dir, investigator_info=investigator_info, agency_info=agency_info, case_info=case_info, classification_info=classification_info)

        evidence_files = onboard.get_evidence_files(project_dir)
        
        onboard.generate_processing_script(project_dir, project_name, evidence_files)

        onboard.display_next_steps(project_dir, project_name)
        return 0

    if not args.project or not args.files:
        parser.print_help()
        print("\n[ERROR] [ERROR] Must specify --project and --files (or use --onboard)")
        return 1
        
    print(f"\n[VALIDATE] Validating input files...")
    valid_files, total_size = validate_input_files(args.files)
    
    if not valid_files:
        print("[ERROR] [ERROR] No valid files to process. Aborting.")
        return 1
    
    # Process the project
    success = process_project(args.project, valid_files, args.output)
    
    if success:
        print(f"\n[OK] [SUCCESS] All done! Check the output directory for results.")
        return 0
    else:
        print(f"\n[ERROR] [ERROR] Processing failed. Check the audit logs for details.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n[INTERRUPT] Interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        logging.getLogger('cli').critical(f"CLI unexpected error: {e}", exc_info=True)
        print(f"\n[ERROR] [ERROR] Unexpected error. Check the audit logs for full stack trace.")
        sys.exit(1)