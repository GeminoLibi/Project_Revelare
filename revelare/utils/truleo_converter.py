#!/usr/bin/env python3
"""
Truleo File Converter Integration
Converts case files to Truleo-accepted formats.
"""
import os
import sys
import shutil
from pathlib import Path
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count

from revelare.config.config import Config
from revelare.utils.logger import get_logger

logger = get_logger("truleo_converter")

# Try to import UFC converter functions
try:
    ufc_path = Path(r"E:\Scripts\UniversalFileConverter")
    if ufc_path.exists():
        sys.path.insert(0, str(ufc_path))
        from file_converter import (
            get_truleo_target_format, get_conversion_function,
            convert_image_to_image, get_image_format_from_ext,
            convert_audio_to_mp3, convert_audio_to_wav, convert_audio_to_m4a,
            convert_video_to_mp4, convert_video_to_mov, convert_video_to_avi,
            convert_csv_to_xlsx, convert_tsv_to_xlsx, convert_json_to_xlsx,
            convert_xml_to_xlsx, convert_docx_to_txt, convert_pdf_to_txt,
            convert_html_to_txt, convert_pptx_to_txt, convert_eml_to_txt,
            convert_md_to_txt, convert_pdf_to_docx
        )
        UFC_AVAILABLE = True
    else:
        logger.warning("UniversalFileConverter not found at E:\\Scripts\\UniversalFileConverter")
        UFC_AVAILABLE = False
except ImportError as e:
    logger.warning(f"Failed to import UFC converter: {e}")
    UFC_AVAILABLE = False


def sanitize_filename(filename: str, max_length: int = 200) -> str:
    """Sanitize filename for safe filesystem use."""
    # Remove or replace problematic characters
    filename = filename.replace('/', '_').replace('\\', '_')
    filename = filename.replace(':', '_').replace('*', '_')
    filename = filename.replace('?', '_').replace('"', '_')
    filename = filename.replace('<', '_').replace('>', '_')
    filename = filename.replace('|', '_')
    
    # Limit length
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        filename = name[:max_length - len(ext)] + ext
    
    return filename


def convert_file_for_truleo(source_path: Path, target_path: Path) -> bool:
    """Convert a file to Truleo format."""
    if not UFC_AVAILABLE:
        logger.error("UFC converter not available")
        return False
    
    source_ext = source_path.suffix.lower()
    target_ext = target_path.suffix.lower()
    
    # Ensure target directory exists
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    # If already in correct format, just copy
    if source_ext == target_ext:
        try:
            shutil.copy2(str(source_path), str(target_path))
            return True
        except Exception as e:
            logger.error(f"Error copying {source_path.name}: {e}")
            return False
    
    # Get conversion function
    conversion_func = get_conversion_function(source_ext, target_ext)
    
    if conversion_func:
        try:
            conversion_func(str(source_path), str(target_path))
            return True
        except Exception as e:
            logger.error(f"Error converting {source_path.name}: {e}")
            return False
    else:
        # No conversion function - try to copy as-is
        logger.warning(f"No converter for {source_ext} -> {target_ext}, copying as-is")
        try:
            shutil.copy2(str(source_path), str(target_path))
            return True
        except Exception as e:
            logger.error(f"Error copying {source_path.name}: {e}")
            return False


def convert_case_for_truleo(case_name: str, output_dir: Optional[Path] = None,
                            skip_dirs: Optional[List[str]] = None) -> Dict[str, any]:
    """
    Convert all files in a case to Truleo-accepted formats.
    
    Args:
        case_name: Name of the case
        output_dir: Output directory (default: cases/{case_name}/truleo)
        skip_dirs: Directories to skip
        
    Returns:
        Dictionary with conversion statistics
    """
    if not UFC_AVAILABLE:
        return {
            'success': False,
            'error': 'UFC converter not available',
            'converted': 0,
            'failed': 0,
            'skipped': 0
        }
    
    if skip_dirs is None:
        skip_dirs = ['__pycache__', 'temp', 'exports', 'reports', 'logs', 'truleo']
    
    case_dir = Path(Config.UPLOAD_FOLDER) / case_name
    if not case_dir.exists():
        return {
            'success': False,
            'error': f'Case directory not found: {case_dir}',
            'converted': 0,
            'failed': 0,
            'skipped': 0
        }
    
    if output_dir is None:
        output_dir = case_dir / 'truleo'
    else:
        output_dir = Path(output_dir) / case_name
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    stats = {
        'success': True,
        'converted': 0,
        'failed': 0,
        'skipped': 0,
        'errors': []
    }
    
    # Collect all files
    files_to_convert = []
    for root, dirs, files in os.walk(case_dir):
        # Filter out skip directories
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        
        for file in files:
            if file.startswith('.'):
                continue
            
            file_path = Path(root) / file
            files_to_convert.append(file_path)
    
    logger.info(f"Found {len(files_to_convert)} files to convert for case {case_name}")
    
    # Determine target format for each file and generate unique names
    conversion_tasks = []
    used_names = set()
    
    for file_path in files_to_convert:
        source_ext = file_path.suffix.lower()
        target_ext = get_truleo_target_format(source_ext)
        
        if not target_ext:
            stats['skipped'] += 1
            continue
        
        # Generate unique target filename
        base_name = sanitize_filename(file_path.stem)
        target_name = f"{case_name}_{base_name}{target_ext}"
        
        # Ensure uniqueness
        counter = 1
        while target_name in used_names:
            target_name = f"{case_name}_{base_name}_{counter}{target_ext}"
            counter += 1
        
        used_names.add(target_name)
        
        target_path = output_dir / target_name
        conversion_tasks.append((file_path, target_path))
    
    # Convert files in parallel
    max_workers = min(cpu_count() * 4, 16)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(convert_file_for_truleo, source, target): (source, target)
            for source, target in conversion_tasks
        }
        
        for future in as_completed(futures):
            source, target = futures[future]
            try:
                success = future.result()
                if success:
                    stats['converted'] += 1
                else:
                    stats['failed'] += 1
                    stats['errors'].append(f"Failed to convert {source.name}")
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append(f"Error converting {source.name}: {e}")
                logger.error(f"Error converting {source.name}: {e}")
    
    logger.info(f"Conversion complete for {case_name}: {stats['converted']} converted, "
                f"{stats['failed']} failed, {stats['skipped']} skipped")
    
    return stats

