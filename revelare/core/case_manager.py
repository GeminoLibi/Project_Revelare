import os
import json
import shutil
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from datetime import datetime

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator
from revelare.core.extractor import run_extraction
from revelare.utils import reporter
import revelare.utils.file_extractor as file_extractor
from revelare.utils.revelare_onboard import RevelareOnboard

logger = get_logger(__name__)
case_logger = RevelareLogger.get_logger('case_manager')

class CaseManager:
    def __init__(self):
        self.onboard = RevelareOnboard()

    def validate_case_name(self, case_name: str) -> Tuple[bool, str]:
        return SecurityValidator.validate_project_name(case_name)

    def create_case_via_onboarding(self, case_number: str, incident_type: str,
                                 investigator_info: Dict, agency_info: Dict,
                                 classification_info: Dict) -> Tuple[bool, str, Optional[str]]:
        try:
            case_info = {
                "case_number": case_number,
                "incident_type": incident_type,
                "description": "",
                "incident_date": datetime.now().strftime('%Y-%m-%d'),
                "created_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            project_dir = self.onboard.create_project_structure(case_info)

            self.onboard.save_case_metadata(
                project_dir,
                investigator_info=investigator_info,
                agency_info=agency_info,
                case_info=case_info,
                classification_info=classification_info
            )

            case_logger.info(f"Case created successfully: {project_dir}")
            return True, f"Case created successfully: {os.path.basename(project_dir)}", project_dir

        except Exception as e:
            error_msg = f"Failed to create case: {str(e)}"
            case_logger.error(error_msg)
            return False, error_msg, None

    def process_evidence_files(self, project_name: str, evidence_files: List[str],
                             callback: Optional[callable] = None) -> Tuple[bool, str]:
        case_logger.info(f"Starting process_evidence_files for project: {project_name} with {len(evidence_files)} evidence files")
        try:
            project_path = os.path.join(Config.UPLOAD_FOLDER, project_name)
            case_logger.info(f"Project path: {project_path}")

            if not os.path.exists(project_path):
                case_logger.error(f"Project directory not found: {project_path}")
                return False, f"Project directory not found: {project_path}"

            extract_path = tempfile.mkdtemp(prefix=f"revelare_{project_name}_extract_")
            case_logger.info(f"Created temp directory: {extract_path}")

            try:
                for evidence_file in evidence_files:
                    if os.path.isfile(evidence_file):
                        if evidence_file.lower().endswith(('.zip', '.rar', '.7z')):
                            file_extractor.safe_extract_archive(evidence_file, extract_path)
                        else:
                            shutil.copy2(evidence_file, os.path.join(extract_path, os.path.basename(evidence_file)))
                    elif os.path.isdir(evidence_file):
                        for root, dirs, files in os.walk(evidence_file):
                            for file in files:
                                src_path = os.path.join(root, file)
                                rel_path = os.path.relpath(src_path, evidence_file)
                                dest_path = os.path.join(extract_path, rel_path)
                                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                                shutil.copy2(src_path, dest_path)

                if callback:
                    callback("Starting extraction...")
                
                temp_files = [str(p) for p in Path(extract_path).rglob('*') if p.is_file()]
                case_logger.info(f"Found {len(temp_files)} files to process in temp directory")
                
                findings = run_extraction(temp_files)
                case_logger.info(f"run_extraction completed, found {len(findings)} finding categories")

                from revelare.cli.suite import update_master_database
                update_master_database(project_name, findings)

                extracted_files_dir = os.path.join(project_path, "extracted_files")
                Path(extracted_files_dir).mkdir(exist_ok=True)

                if callback:
                    callback("Organizing files...")
                file_extractor.extract_and_rename_files(extract_path, project_name, extracted_files_dir)

                with open(os.path.join(project_path, 'raw_findings.json'), 'w', encoding='utf-8') as f:
                    json.dump(findings, f, indent=4, ensure_ascii=False)

                if callback:
                    callback("Generating report...")
                ip_addresses = [v for k in findings if 'IPv4' in k for v in findings[k].keys()]
                report_generator = reporter.ReportGenerator()
                enriched_ips = report_generator.enrich_ips(ip_addresses)
                html_report = report_generator.generate_report(project_name, findings, enriched_ips)

                with open(os.path.join(project_path, 'report.html'), 'w', encoding='utf-8') as f:
                    f.write(html_report)

                # Export portable reader package
                try:
                    from revelare.utils.exporter import export_reader_package
                    export_path = export_reader_package(project_name)
                    case_logger.info(f"Exported portable report package: {export_path}")
                except Exception as e:
                    case_logger.warning(f"Failed to export portable report package: {e}")

                file_extractor.cleanup_temp_files(extract_path)

                case_logger.info(f"Evidence processing completed for {project_name}")
                return True, f"Processing completed successfully for {project_name}"

            except Exception as e:
                file_extractor.cleanup_temp_files(extract_path)
                error_msg = f"Processing failed: {str(e)}"
                case_logger.error(error_msg)
                return False, error_msg

        except Exception as e:
            error_msg = f"Evidence processing setup failed: {str(e)}"
            case_logger.error(error_msg)
            return False, error_msg

    def get_case_directory_tree(self, case_name: str) -> Optional[Dict[str, Any]]:
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            if not os.path.exists(case_path):
                case_logger.warning(f"Case directory does not exist: {case_path}")
                return None
            
            # Check if it's actually a directory
            if not os.path.isdir(case_path):
                case_logger.warning(f"Case path is not a directory: {case_path}")
                return None

            def format_file_size(size_bytes):
                if size_bytes is None or size_bytes == 0:
                    return "0 B"
                size_names = ["B", "KB", "MB", "GB", "TB"]
                i = 0
                while size_bytes >= 1024.0 and i < len(size_names) - 1:
                    size_bytes /= 1024.0
                    i += 1
                return f"{size_bytes:.2f} {size_names[i]}" if i > 0 else f"{int(size_bytes)} {size_names[i]}"

            def build_tree(path: str, name: str) -> Dict[str, Any]:
                try:
                    if os.path.isfile(path):
                        size = os.path.getsize(path)
                        return {
                            "name": name, "type": "file", "size": size,
                            "formatted_size": format_file_size(size),
                            "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                        }
                    else:
                        children = []
                        try:
                            for item in sorted(os.listdir(path)):
                                item_path = os.path.join(path, item)
                                
                                # Normalize long paths instead of skipping them
                                if len(item_path) > 250:
                                    from revelare.utils.file_extractor import normalize_file_path
                                    normalized_path, original_path = normalize_file_path(item_path, case_name)
                                    
                                    # If normalization created a different path, rename the file
                                    if normalized_path != original_path:
                                        try:
                                            os.rename(original_path, normalized_path)
                                            logger.info(f"Normalized long path: {original_path} -> {normalized_path}")
                                            item_path = normalized_path
                                            item = os.path.basename(normalized_path)
                                        except Exception as e:
                                            logger.error(f"Failed to normalize path {original_path}: {e}")
                                            children.append({
                                                "name": f"{item} (path too long - normalization failed)",
                                                "type": "file",
                                                "size": 0,
                                                "formatted_size": "0 B",
                                                "modified": "unknown"
                                            })
                                            continue
                                
                                children.append(build_tree(item_path, item))
                        except (PermissionError, OSError) as e:
                            # Handle permission errors and path too long errors
                            if "path too long" in str(e).lower() or "cannot find the path" in str(e).lower():
                                children.append({
                                    "name": f"Directory (path too long - skipped)",
                                    "type": "file",
                                    "size": 0,
                                    "formatted_size": "0 B",
                                    "modified": "unknown"
                                })
                            else:
                                pass  # Other permission errors are silently ignored
                        return {
                            "name": name, "type": "directory", "children": children,
                            "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                        }
                except (OSError, IOError) as e:
                    # Handle any other file system errors
                    return {
                        "name": f"{name} (error: {str(e)[:50]}...)",
                        "type": "file",
                        "size": 0,
                        "formatted_size": "0 B",
                        "modified": "unknown"
                    }
            return build_tree(case_path, case_name)
        except Exception as e:
            case_logger.error(f"Failed to build directory tree for {case_name}: {e}")
            # Return a basic tree structure instead of None to prevent "Case not found" error
            return {
                "name": case_name,
                "type": "directory",
                "children": [{
                    "name": "Error loading directory tree",
                    "type": "file",
                    "size": 0,
                    "formatted_size": "0 B",
                    "modified": "unknown"
                }],
                "modified": datetime.now().isoformat()
            }

    def get_available_cases(self) -> List[Dict[str, Any]]:
        try:
            cases = []
            cases_dir = Config.UPLOAD_FOLDER
            if os.path.exists(cases_dir):
                for item in os.listdir(cases_dir):
                    case_path = os.path.join(cases_dir, item)
                    if os.path.isdir(case_path):
                        has_report = os.path.exists(os.path.join(case_path, 'report.html'))
                        findings_file = os.path.join(case_path, 'raw_findings.json')
                        findings_count = 0
                        if os.path.exists(findings_file):
                            try:
                                with open(findings_file, 'r', encoding='utf-8') as f:
                                    data = json.load(f)
                                    for category, items in data.items():
                                        if category != 'Processing_Summary' and isinstance(items, dict):
                                            findings_count += len(items)
                            except:
                                pass
                        
                        email_archives = []
                        try:
                            from revelare.utils.mbox_viewer import EmailBrowser
                            browser = EmailBrowser()
                            email_archives = browser.get_email_archives_in_case(item)
                        except Exception as e:
                            # Do not warn repeatedly if optional email viewer is not installed
                            if "mbox_viewer" not in str(e):
                                case_logger.warning(f"Error checking email archives for case {item}: {e}")
                        
                        cases.append({
                            "name": item, "path": case_path, "has_report": has_report,
                            "findings_count": findings_count, "email_archives": email_archives,
                            "email_archive_count": len(email_archives),
                            "created": datetime.fromtimestamp(os.path.getctime(case_path)).isoformat()
                        })
            return sorted(cases, key=lambda x: x['created'], reverse=True)
        except Exception as e:
            case_logger.error(f"Failed to get available cases: {e}")
            return []

    def get_evidence_files_for_case(self, case_name: str) -> List[str]:
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            evidence_dir = os.path.join(case_path, 'evidence')
            if not os.path.exists(evidence_dir):
                return []
            
            evidence_files = []
            for root, dirs, files in os.walk(evidence_dir):
                for file in files:
                    evidence_files.append(os.path.join(root, file))
            return evidence_files
        except Exception as e:
            case_logger.error(f"Failed to get evidence files for case {case_name}: {e}")
            return []

    def reanalyze_case(self, case_name: str, callback: Optional[callable] = None) -> Tuple[bool, str]:
        try:
            case_logger.info(f"Starting re-analysis for case: {case_name}")
            evidence_files = self.get_evidence_files_for_case(case_name)
            if not evidence_files:
                return False, f"No evidence files found for case '{case_name}'"
            return self.process_evidence_files(case_name, evidence_files, callback)
        except Exception as e:
            error_msg = f"Re-analysis failed for case '{case_name}': {str(e)}"
            case_logger.error(error_msg)
            return False, error_msg

    def get_case_notes(self, case_name: str) -> Dict[str, Any]:
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            notes_file = os.path.join(case_path, 'notes.json')
            if not os.path.exists(notes_file):
                return {"case_notes": "", "file_notes": {}}
            with open(notes_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            case_logger.error(f"Failed to load notes for case {case_name}: {e}")
            return {"case_notes": "", "file_notes": {}}

    def save_case_notes(self, case_name: str, notes_data: Dict[str, Any]) -> bool:
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            notes_file = os.path.join(case_path, 'notes.json')
            os.makedirs(case_path, exist_ok=True)
            with open(notes_file, 'w', encoding='utf-8') as f:
                json.dump(notes_data, f, indent=2, ensure_ascii=False)
            case_logger.info(f"Notes saved for case {case_name}")
            return True
        except Exception as e:
            case_logger.error(f"Failed to save notes for case {case_name}: {e}")
            return False

case_manager = CaseManager()