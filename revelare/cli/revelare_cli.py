import os
import sys
import argparse
import json
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
    from revelare.core.findings_store import write_findings_artifacts
    write_findings_artifacts(project_dir, findings)
    print("[OK] JSON export saved: indicators.json")
    print("[OK] Findings snapshot saved: raw_findings.json")
    print("[OK] CSV export saved: indicators.csv")

def process_project(project_name: str, input_files: List[str], output_dir: str, args) -> bool:
    is_name_valid, error_msg = SecurityValidator.validate_project_name(project_name)
    if not is_name_valid:
        cli_logger.critical(f"Invalid project name: {error_msg}")
        return False
        
    project_dir = os.path.abspath(os.path.join(output_dir, project_name))
    Path(project_dir).mkdir(parents=True, exist_ok=True)
    
    from revelare.utils.file_extractor import mkdtemp_in_script_dir
    from revelare.core.source_ingest import (
        ARCHIVE_EXTENSIONS,
        clear_source_registry,
        stage_sources_to_temp,
        write_ingest_manifest,
    )
    temp_working_dir = Path(mkdtemp_in_script_dir(prefix=f"revelare_{project_name}_temp_"))
    
    print(f"\n[START] Starting Project: {project_name}")
    
    try:
        print(f"\n[INGEST] Staging temp copies (source path recorded, no vault copy)...")
        clear_source_registry()
        ingest_records = stage_sources_to_temp(input_files, str(temp_working_dir))
        for i, rec in enumerate(ingest_records, 1):
            print(f"  [{i}/{len(ingest_records)}] Source: {rec.get('source_path')}")
            
        # Collect staged files, skip archives (already extracted into temp)
        all_extracted_paths = []
        for p in temp_working_dir.rglob('*'):
            if p.is_file():
                if p.suffix.lower() in ARCHIVE_EXTENSIONS:
                    continue
                all_extracted_paths.append(str(p))
        
        print(f"\n[EXTRACT] Running indicator extraction on {len(all_extracted_paths)} files...")
        
        original_cwd = os.getcwd()
        os.chdir(temp_working_dir)
        try:
            findings = run_extraction(all_extracted_paths)
        finally:
            os.chdir(original_cwd)
        
        total_findings = sum(len(items) for k, items in findings.items() if k != 'Processing_Summary')
        print(f"[OK] Found {total_findings} indicators.")

        write_ingest_manifest(project_dir, ingest_records)

        report_generator = reporter.ReportGenerator()
        ip_addresses = [v for k in findings if 'IPv4' in k for v in findings[k].keys()]
        enriched_ips = report_generator.enrich_ips(ip_addresses)
        
        from revelare.core.findings_store import write_report_html
        from revelare.core.database import update_master_database
        report_html = report_generator.generate_report(project_name, findings, enriched_ips)
        write_report_html(project_dir, project_name, report_html)
        print("[OK] Report generated: report.html")
        
        _export_results(project_dir, findings, project_name)
        update_master_database(project_name, findings)
        
        print(f"\n[SUCCESS] Project '{project_name}' completed successfully!")
        print(f"[INFO] Outputs saved to: {project_dir}")
        return True
        
    except Exception as e:
        cli_logger.error(f"CLI project processing failed: {e}", exc_info=True)
        print(f"[ERROR] Critical processing failure. Check logs for details.")
        return False
        
    finally:
        file_extractor.cleanup_temp_files(str(temp_working_dir))
        clear_source_registry()
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
    
    # Case synchronization commands
    parser.add_argument('--sync', metavar='DIR', help='Synchronize cases from external directory')
    parser.add_argument('--sync-no-process', action='store_true', help='Sync without processing files')
    parser.add_argument('--check-duplicates', action='store_true', help='Check for cross-case duplicates')
    parser.add_argument('--convert-truleo', metavar='CASE', help='Convert case files to Truleo format')
    
    # Batch processing commands
    parser.add_argument('--reprocess-all', action='store_true', help='Reprocess all existing cases')
    parser.add_argument('--clean-all', action='store_true', help='Clean false positives from all cases')
    
    # Case import/export commands
    parser.add_argument('--export-case', metavar='CASE', help='Export a case to standardized format')
    parser.add_argument('--export-output', metavar='PATH', help='Output path for export (default: case/exports/)')
    parser.add_argument('--export-indicators-only', action='store_true', help='Export only indicators (no files)')
    parser.add_argument('--export-no-extracted', action='store_true', help='Exclude extracted_files directory from export')
    parser.add_argument('--import-case', metavar='FILE', help='Import a case from exported zip file')
    parser.add_argument('--import-name', metavar='NAME', help='New name for imported case (optional)')
    parser.add_argument('--import-overwrite', action='store_true', help='Overwrite existing case if it exists')

    # Corpus export commands
    parser.add_argument('--corpus-export', metavar='CASES', help='Export identifier corpus (comma-separated case names, or "all")')
    parser.add_argument('--corpus-primary', default='__case__', help='Primary identifier type (default: __case__)')
    parser.add_argument('--corpus-columns', metavar='TYPES', help='Comma-separated identifier columns to include')
    parser.add_argument('--corpus-format', choices=['csv', 'flat_csv', 'xlsx', 'json'], default='csv', help='Export format')
    parser.add_argument('--corpus-output', metavar='PATH', help='Output file path')
    parser.add_argument('--corpus-filter', metavar='TEXT', help='Filter cases by name substring when using --corpus-export all')
    
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
    
    if args.sync:
        from revelare.utils.unified_manager import UnifiedCaseManager
        external_dir = args.sync
        process_files = not args.sync_no_process
        
        print(f"\n[SYNC] Synchronizing cases from {external_dir}")
        manager = UnifiedCaseManager(external_dir)
        results = manager.run_full_sync(
            process_files=process_files,
            check_duplicates=True,
            check_cross_case_duplicates=True,
            convert_to_truleo=False
        )
        
        stats = results.get('sync_stats', {})
        print(f"\n[SYNC] Complete:")
        print(f"  Cases discovered: {stats.get('cases_discovered', 0)}")
        print(f"  Cases created: {stats.get('cases_created', 0)}")
        print(f"  Cases updated: {stats.get('cases_updated', 0)}")
        print(f"  Files processed: {stats.get('files_processed', 0)}")
        print(f"  Duplicates skipped: {stats.get('duplicates_skipped', 0)}")
        
        if results.get('duplicate_report') and results['duplicate_report'].get('duplicate_groups', 0) > 0:
            print(f"  Cross-case duplicates: {results['duplicate_report']['duplicate_groups']}")
            print(f"  Report: {results['duplicate_report'].get('file', 'N/A')}")
        
        if results.get('errors'):
            print(f"\n[WARNING] {len(results['errors'])} errors encountered")
            for error in results['errors'][:5]:
                print(f"  - {error}")
        
        return 0
    
    if args.check_duplicates:
        from revelare.utils.file_deduplication import find_cross_case_duplicates, format_duplicate_report
        from pathlib import Path
        
        print("\n[DUPLICATES] Checking for cross-case duplicates...")
        duplicates = find_cross_case_duplicates(Path(Config.UPLOAD_FOLDER))
        
        if duplicates:
            report = format_duplicate_report(duplicates)
            report_file = Path(Config.UPLOAD_FOLDER) / f"duplicate_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"Duplicate Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
                f.write(report)
            
            print(f"\n[DUPLICATES] Found {len(duplicates)} duplicate file groups")
            print(f"  Report saved to: {report_file}")
            print("\n" + report)
        else:
            print("\n[DUPLICATES] No cross-case duplicates found")
        
        return 0
    
    if args.convert_truleo:
        from revelare.utils.truleo_converter import convert_case_for_truleo
        
        case_name = args.convert_truleo
        print(f"\n[TRULEO] Converting case '{case_name}' to Truleo format...")
        result = convert_case_for_truleo(case_name)
        
        if result.get('success'):
            print(f"[TRULEO] Complete:")
            print(f"  Converted: {result.get('converted', 0)}")
            print(f"  Failed: {result.get('failed', 0)}")
            print(f"  Skipped: {result.get('skipped', 0)}")
        else:
            print(f"[TRULEO] Failed: {result.get('error', 'Unknown error')}")
            return 1
        
        return 0
    
    if args.reprocess_all:
        print("\n[REPROCESS] Reprocessing all cases...")
        from utilities.reprocess_all_cases import reprocess_all_cases
        reprocess_all_cases()
        return 0
    
    if args.clean_all:
        print("\n[CLEAN] Cleaning false positives from all cases...")
        from utilities.clean_all_cases import clean_all_cases
        clean_all_cases()
        return 0
    
    if args.export_case:
        from revelare.utils.case_import_export import CaseExporter
        
        case_name = args.export_case
        output_path = args.export_output or os.path.join(Config.UPLOAD_FOLDER, case_name, 'exports')
        include_files = not args.export_indicators_only
        include_extracted = not args.export_no_extracted
        
        print(f"\n[EXPORT] Exporting case '{case_name}'...")
        print(f"  Type: {'Full (with files)' if include_files else 'Indicators only'}")
        if include_files:
            print(f"  Include extracted files: {include_extracted}")
        
        exporter = CaseExporter()
        success, message, export_path = exporter.export_case(
            case_name,
            output_path,
            include_files=include_files,
            include_extracted=include_extracted
        )
        
        if success:
            print(f"[EXPORT] Success: {message}")
            print(f"  Export file: {export_path}")
        else:
            print(f"[EXPORT] Failed: {message}")
            return 1
        
        return 0

    if args.corpus_export:
        from revelare.utils.corpus_exporter import CorpusExporter, PRIMARY_CASE

        exporter = CorpusExporter()
        if args.corpus_export.lower() == 'all':
            case_names = [case['name'] for case in exporter.discover_cases()]
            if args.corpus_filter:
                needle = args.corpus_filter.lower()
                case_names = [name for name in case_names if needle in name.lower()]
        else:
            case_names = [item.strip() for item in args.corpus_export.split(',') if item.strip()]

        if not case_names:
            print("[CORPUS] No cases matched the export request.")
            return 1

        column_types = []
        if args.corpus_columns:
            column_types = [item.strip() for item in args.corpus_columns.split(',') if item.strip()]
        else:
            column_types = [
                item for item in exporter.get_available_identifier_types(case_names)
                if item != PRIMARY_CASE
            ]

        print(f"\n[CORPUS] Building corpus for {len(case_names)} case(s)...")
        print(f"  Primary key: {args.corpus_primary}")
        print(f"  Columns: {', '.join(column_types[:8])}{'...' if len(column_types) > 8 else ''}")

        corpus = exporter.build_export_bundle(
            case_names=case_names,
            primary_key=args.corpus_primary,
            column_types=column_types,
            include_cross_links=True,
        )

        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_name = f"revelare_corpus_{len(case_names)}cases_{stamp}"
        if args.corpus_output:
            output_path = args.corpus_output
        elif args.corpus_format == 'json':
            output_path = os.path.join(Config.UPLOAD_FOLDER, f"{default_name}.json")
        elif args.corpus_format == 'xlsx':
            output_path = os.path.join(Config.UPLOAD_FOLDER, f"{default_name}.xlsx")
        elif args.corpus_format == 'flat_csv':
            output_path = os.path.join(Config.UPLOAD_FOLDER, f"revelare_identifiers_{len(case_names)}cases_{stamp}.csv")
        else:
            output_path = os.path.join(Config.UPLOAD_FOLDER, f"{default_name}.zip")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        if args.corpus_format == 'json':
            with open(output_path, 'wb') as handle:
                handle.write(exporter.export_json(corpus))
        elif args.corpus_format == 'xlsx':
            with open(output_path, 'wb') as handle:
                handle.write(exporter.export_excel(corpus))
        elif args.corpus_format == 'flat_csv':
            with open(output_path, 'wb') as handle:
                handle.write(exporter.export_csv(corpus.get('flat_rows', [])))
        else:
            with open(output_path, 'wb') as handle:
                handle.write(exporter.export_csv_bundle(corpus))

        meta = corpus['meta']
        print(f"[CORPUS] Export complete:")
        print(f"  Subjects: {meta.get('subject_count', 0)}")
        print(f"  Flat rows: {meta.get('flat_row_count', 0)}")
        print(f"  Connections: {meta.get('connection_count', 0)}")
        print(f"  Cross-links: {meta.get('cross_link_count', 0)}")
        print(f"  Output: {output_path}")
        return 0

    if args.import_case:
        from revelare.utils.case_import_export import CaseImporter
        
        export_file = args.import_case
        if not os.path.exists(export_file):
            print(f"[ERROR] Export file not found: {export_file}")
            return 1
        
        print(f"\n[IMPORT] Importing case from '{export_file}'...")
        
        # Validate export file first
        importer = CaseImporter()
        is_valid, valid_msg, manifest = importer.validate_export_file(export_file)
        
        if not is_valid:
            print(f"[IMPORT] Validation failed: {valid_msg}")
            return 1
        
        if manifest:
            print(f"  Export type: {manifest.get('export_type', 'unknown')}")
            print(f"  Original case: {manifest.get('case_name', 'unknown')}")
            print(f"  Export date: {manifest.get('export_date', 'unknown')}")
            print(f"  Indicators: {manifest.get('indicators_count', 0)}")
            if manifest.get('includes_files'):
                print(f"  Files included: Yes")
                if manifest.get('files'):
                    print(f"    Evidence files: {manifest['files'].get('evidence_count', 0)}")
                    print(f"    Extracted files: {manifest['files'].get('extracted_count', 0)}")
            else:
                print(f"  Files included: No (indicators only)")
        
        target_name = args.import_name or None
        overwrite = args.import_overwrite
        
        if target_name:
            print(f"  Target case name: {target_name}")
        if overwrite:
            print(f"  Overwrite mode: Enabled")
        
        success, message, case_path = importer.import_case(
            export_file,
            target_case_name=target_name,
            overwrite=overwrite
        )
        
        if success:
            print(f"[IMPORT] Success: {message}")
            print(f"  Case path: {case_path}")
        else:
            print(f"[IMPORT] Failed: {message}")
            return 1
        
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