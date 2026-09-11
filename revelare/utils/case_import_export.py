"""
Standardized Case Import/Export Module
Supports exporting cases with files or indicators-only, and importing them back.
"""
import os
import json
import shutil
import zipfile
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.core.case_manager import CaseManager

logger = get_logger(__name__)

# Export format version for compatibility checking
EXPORT_FORMAT_VERSION = "1.0"

# Required files for a valid case export (findings JSON is checked separately)
REQUIRED_CASE_FILES = []

# Optional files that may be included
OPTIONAL_CASE_FILES = [
    'case_metadata.json',
    'raw_findings.json',
    'report.html',
    'indicators.json',
    'indicators.csv',
    'ingest_manifest.json',
]


class CaseExporter:
    """Handles exporting cases in standardized formats."""
    
    def __init__(self):
        self.case_manager = CaseManager()
    
    def export_case(self, case_name: str, output_path: str, 
                   include_files: bool = True, 
                   include_extracted: bool = True) -> Tuple[bool, str, Optional[str]]:
        """
        Export a case to a standardized format.
        
        Args:
            case_name: Name of the case to export
            output_path: Path where the export file will be created
            include_files: If True, include evidence files (full export)
            include_extracted: If True, include extracted_files directory
            
        Returns:
            Tuple of (success, message, export_file_path)
        """
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            
            if not os.path.exists(case_path):
                return False, f"Case '{case_name}' not found", None
            
            from revelare.core.findings_store import load_findings
            if load_findings(case_path) is None:
                return False, "Missing findings JSON (raw_findings.json or indicators.json)", None
            
            # Create export manifest
            manifest = self._create_export_manifest(case_name, case_path, include_files, include_extracted)
            
            # Create temporary directory for export
            with tempfile.TemporaryDirectory() as temp_dir:
                export_dir = os.path.join(temp_dir, case_name)
                os.makedirs(export_dir, exist_ok=True)
                
                # Copy required files
                for req_file in REQUIRED_CASE_FILES:
                    src = os.path.join(case_path, req_file)
                    dst = os.path.join(export_dir, req_file)
                    shutil.copy2(src, dst)
                    logger.debug(f"Copied {req_file}")
                
                # Copy optional files if they exist
                for opt_file in OPTIONAL_CASE_FILES:
                    src = os.path.join(case_path, opt_file)
                    if os.path.exists(src):
                        dst = os.path.join(export_dir, opt_file)
                        shutil.copy2(src, dst)
                        logger.debug(f"Copied {opt_file}")
                
                # Copy files if requested
                if include_files:
                    # Copy evidence directory
                    evidence_dir = os.path.join(case_path, 'evidence')
                    if os.path.exists(evidence_dir):
                        dst_evidence = os.path.join(export_dir, 'evidence')
                        shutil.copytree(evidence_dir, dst_evidence, dirs_exist_ok=True)
                        logger.debug(f"Copied evidence directory")
                    
                    # Copy extracted_files if requested
                    if include_extracted:
                        extracted_dir = os.path.join(case_path, 'extracted_files')
                        if os.path.exists(extracted_dir):
                            dst_extracted = os.path.join(export_dir, 'extracted_files')
                            shutil.copytree(extracted_dir, dst_extracted, dirs_exist_ok=True)
                            logger.debug(f"Copied extracted_files directory")
                
                # Save manifest
                manifest_path = os.path.join(export_dir, 'export_manifest.json')
                with open(manifest_path, 'w', encoding='utf-8') as f:
                    json.dump(manifest, f, indent=2, ensure_ascii=False)
                
                # Create zip file
                export_filename = self._generate_export_filename(case_name, include_files)
                if not output_path.endswith('.zip'):
                    output_path = os.path.join(output_path, export_filename)
                else:
                    # If output_path is a file, use it directly
                    export_filename = os.path.basename(output_path)
                
                # Ensure output directory exists
                output_dir = os.path.dirname(output_path)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                
                # Create zip
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, dirs, files in os.walk(export_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, export_dir)
                            zipf.write(file_path, arcname)
                            logger.debug(f"Added to zip: {arcname}")
                
                file_size = os.path.getsize(output_path)
                size_mb = file_size / (1024 * 1024)
                
                logger.info(f"Exported case '{case_name}' to '{output_path}' ({size_mb:.2f} MB)")
                return True, f"Case exported successfully ({size_mb:.2f} MB)", output_path
                
        except Exception as e:
            error_msg = f"Failed to export case: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return False, error_msg, None
    
    def _create_export_manifest(self, case_name: str, case_path: str, 
                                include_files: bool, include_extracted: bool) -> Dict[str, Any]:
        """Create export manifest with metadata."""
        manifest = {
            'format_version': EXPORT_FORMAT_VERSION,
            'export_type': 'full' if include_files else 'indicators_only',
            'case_name': case_name,
            'export_date': datetime.now().isoformat(),
            'revelare_version': '2.5',
            'includes_files': include_files,
            'includes_extracted': include_extracted,
            'files': {}
        }
        
        # Load case metadata
        metadata_path = os.path.join(case_path, 'case_metadata.json')
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r', encoding='utf-8') as f:
                case_metadata = json.load(f)
                manifest['case_metadata'] = case_metadata.get('case_metadata', {})
        
        # Count files
        if include_files:
            evidence_dir = os.path.join(case_path, 'evidence')
            if os.path.exists(evidence_dir):
                evidence_files = list(Path(evidence_dir).rglob('*'))
                manifest['files']['evidence_count'] = len([f for f in evidence_files if f.is_file()])
            
            if include_extracted:
                extracted_dir = os.path.join(case_path, 'extracted_files')
                if os.path.exists(extracted_dir):
                    extracted_files = list(Path(extracted_dir).rglob('*'))
                    manifest['files']['extracted_count'] = len([f for f in extracted_files if f.is_file()])
        
        # Count indicators
        from revelare.core.findings_store import count_findings, load_findings
        findings = load_findings(case_path)
        if findings is not None:
            manifest['indicators_count'] = count_findings(findings)
            manifest['categories'] = [k for k in findings.keys()
                                     if k != 'Processing_Summary' and isinstance(findings[k], dict)]
        
        return manifest
    
    def _generate_export_filename(self, case_name: str, include_files: bool) -> str:
        """Generate export filename."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        export_type = 'full' if include_files else 'indicators'
        return f"{case_name}_export_{export_type}_{timestamp}.zip"


class CaseImporter:
    """Handles importing cases from standardized export formats."""
    
    def __init__(self):
        self.case_manager = CaseManager()
    
    def import_case(self, export_file_path: str, 
                   target_case_name: Optional[str] = None,
                   overwrite: bool = False) -> Tuple[bool, str, Optional[str]]:
        """
        Import a case from an exported zip file.
        
        Args:
            export_file_path: Path to the export zip file
            target_case_name: Optional new name for the case (if None, uses original name)
            overwrite: If True, overwrite existing case
            
        Returns:
            Tuple of (success, message, case_path)
        """
        try:
            if not os.path.exists(export_file_path):
                return False, f"Export file not found: {export_file_path}", None
            
            if not export_file_path.endswith('.zip'):
                return False, "Export file must be a .zip file", None
            
            # Extract to temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                extract_dir = os.path.join(temp_dir, 'import')
                os.makedirs(extract_dir, exist_ok=True)
                
                # Extract zip
                with zipfile.ZipFile(export_file_path, 'r') as zipf:
                    zipf.extractall(extract_dir)
                
                # Find case directory (should be the only top-level directory)
                extracted_items = os.listdir(extract_dir)
                if not extracted_items:
                    return False, "Export file is empty or invalid", None
                
                # Case directory is the first (and should be only) directory
                case_dir_name = extracted_items[0]
                case_dir = os.path.join(extract_dir, case_dir_name)
                
                if not os.path.isdir(case_dir):
                    return False, "Invalid export format: case directory not found", None
                
                # Load and validate manifest
                manifest_path = os.path.join(case_dir, 'export_manifest.json')
                if not os.path.exists(manifest_path):
                    return False, "Invalid export: manifest file not found", None
                
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
                
                # Validate format version
                format_version = manifest.get('format_version', '0.0')
                if format_version != EXPORT_FORMAT_VERSION:
                    logger.warning(f"Export format version {format_version} differs from current {EXPORT_FORMAT_VERSION}")
                
                # Determine case name
                original_case_name = manifest.get('case_name', case_dir_name)
                if target_case_name:
                    case_name = target_case_name
                else:
                    case_name = original_case_name
                
                # Validate case name
                is_valid, error_msg = self.case_manager.validate_case_name(case_name)
                if not is_valid:
                    return False, f"Invalid case name: {error_msg}", None
                
                # Check if case exists
                case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
                if os.path.exists(case_path) and not overwrite:
                    return False, f"Case '{case_name}' already exists. Use overwrite=True to replace.", None
                
                # Create or clear case directory
                if os.path.exists(case_path):
                    if overwrite:
                        shutil.rmtree(case_path)
                    else:
                        return False, f"Case '{case_name}' already exists", None
                
                os.makedirs(case_path, exist_ok=True)
                
                # Copy required files
                for req_file in REQUIRED_CASE_FILES:
                    src = os.path.join(case_dir, req_file)
                    if not os.path.exists(src):
                        return False, f"Missing required file: {req_file}", None
                    dst = os.path.join(case_path, req_file)
                    shutil.copy2(src, dst)
                    logger.debug(f"Copied {req_file}")
                
                # Copy optional files
                for opt_file in OPTIONAL_CASE_FILES:
                    src = os.path.join(case_dir, opt_file)
                    if os.path.exists(src):
                        dst = os.path.join(case_path, opt_file)
                        shutil.copy2(src, dst)
                        logger.debug(f"Copied {opt_file}")
                
                # Copy directories if they exist
                if manifest.get('includes_files', False):
                    # Copy evidence
                    src_evidence = os.path.join(case_dir, 'evidence')
                    if os.path.exists(src_evidence):
                        dst_evidence = os.path.join(case_path, 'evidence')
                        shutil.copytree(src_evidence, dst_evidence, dirs_exist_ok=True)
                        logger.debug("Copied evidence directory")
                    
                    # Copy extracted_files if included
                    if manifest.get('includes_extracted', False):
                        src_extracted = os.path.join(case_dir, 'extracted_files')
                        if os.path.exists(src_extracted):
                            dst_extracted = os.path.join(case_path, 'extracted_files')
                            shutil.copytree(src_extracted, dst_extracted, dirs_exist_ok=True)
                            logger.debug("Copied extracted_files directory")
                
                # Update case metadata with import info
                metadata_path = os.path.join(case_path, 'case_metadata.json')
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                    
                    # Add import information
                    if 'import_info' not in metadata:
                        metadata['import_info'] = []
                    
                    metadata['import_info'].append({
                        'imported_date': datetime.now().isoformat(),
                        'original_case_name': original_case_name,
                        'export_date': manifest.get('export_date'),
                        'export_type': manifest.get('export_type'),
                        'format_version': format_version
                    })
                    
                    with open(metadata_path, 'w', encoding='utf-8') as f:
                        json.dump(metadata, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Imported case '{case_name}' from '{export_file_path}'")
                return True, f"Case '{case_name}' imported successfully", case_path
                
        except Exception as e:
            error_msg = f"Failed to import case: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return False, error_msg, None
    
    def validate_export_file(self, export_file_path: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validate an export file without importing it.
        
        Returns:
            Tuple of (is_valid, message, manifest_dict)
        """
        try:
            if not os.path.exists(export_file_path):
                return False, "Export file not found", None
            
            if not export_file_path.endswith('.zip'):
                return False, "Export file must be a .zip file", None
            
            with tempfile.TemporaryDirectory() as temp_dir:
                extract_dir = os.path.join(temp_dir, 'validate')
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(export_file_path, 'r') as zipf:
                    zipf.extractall(extract_dir)
                
                # Find manifest
                manifest_path = None
                for root, dirs, files in os.walk(extract_dir):
                    if 'export_manifest.json' in files:
                        manifest_path = os.path.join(root, 'export_manifest.json')
                        break
                
                if not manifest_path:
                    return False, "Invalid export: manifest file not found", None
                
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
                
                # Check required files
                case_dir = os.path.dirname(manifest_path)
                missing_files = []
                for req_file in REQUIRED_CASE_FILES:
                    if not os.path.exists(os.path.join(case_dir, req_file)):
                        missing_files.append(req_file)
                
                if missing_files:
                    return False, f"Missing required files: {', '.join(missing_files)}", manifest
                
                return True, "Export file is valid", manifest
                
        except Exception as e:
            return False, f"Validation error: {str(e)}", None
