import os
import csv
import re
import tempfile
import zipfile
import time
from typing import List, Dict, Any, Tuple
from pathlib import Path
import logging

from revelare.config.config import Config
from revelare.utils.logger import get_logger

class StringSearchEngine:
    def __init__(self, logger_instance=None):
        self.logger = logger_instance or get_logger(__name__)
        self.interrupted = False
    
    def search_directory(self, directory: str, search_strings: List[str], 
                         context_chars: int = 50, file_extensions: List[str] = None, use_regex: bool = False) -> List[Dict[str, Any]]:
        all_results = []
        
        if not os.path.isdir(directory):
            self.logger.error(f"Directory does not exist: {directory}")
            return all_results
        
        files_to_search = []
        for root, _, files in os.walk(directory):
            for file in files:
                if self.interrupted: break
                file_path = os.path.join(root, file)
                if not file_extensions or any(file_path.lower().endswith(ext) for ext in file_extensions):
                    files_to_search.append(file_path)
            if self.interrupted: break
        
        self.logger.info(f"Found {len(files_to_search)} files to search in {directory}")
        
        for i, file_path in enumerate(files_to_search):
            if self.interrupted:
                self.logger.warning("Search interrupted by user")
                break
            
            self.logger.debug(f"Processing file {i+1}/{len(files_to_search)}: {os.path.basename(file_path)}")
            
            try:
                results = self._search_in_item(file_path, search_strings, context_chars, use_regex)
                all_results.extend(results)
            except Exception as e:
                self.logger.error(f"Error processing {file_path}: {e}")
        
        self.logger.info(f"Search completed: {len(all_results)} total matches found")
        return all_results

    def _search_in_item(self, item_path: str, search_strings: List[str], context_chars: int, use_regex: bool, archive_depth: int = 0, processed_archives: set = None) -> List[Dict[str, Any]]:
        if processed_archives is None:
            processed_archives = set()
        
        if self._is_archive_file(item_path):
            # Normalize path to prevent infinite loops
            normalized_path = os.path.normpath(item_path)
            if normalized_path not in processed_archives:
                processed_archives.add(normalized_path)
                return self._search_in_archive(item_path, search_strings, context_chars, use_regex, archive_depth, processed_archives)
            else:
                self.logger.debug(f"Skipping already processed archive: {item_path}")
                return []
        else:
            return self._search_in_file(item_path, search_strings, context_chars, use_regex, archive_depth)

    def _search_in_file(self, file_path: str, search_strings: List[str], 
                        context_chars: int, use_regex: bool, archive_depth: int) -> List[Dict[str, Any]]:
        results = []
        try:
            content = self._read_file_safely(file_path)
            if not content: return results
            
            patterns = []
            if use_regex:
                try:
                    patterns.append((search_strings[0], re.compile(search_strings[0], re.IGNORECASE)))
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern '{search_strings[0]}': {e}")
                    return results
            else:
                patterns = [(s, re.compile(re.escape(s), re.IGNORECASE)) for s in search_strings]

            for search_string, pattern in patterns:
                for match in pattern.finditer(content):
                    start, end = match.start(), match.end()
                    context_start = max(0, start - context_chars)
                    context_end = min(len(content), end + context_chars)
                    context = content[context_start:context_end].replace('\n', ' ').replace('\r', '').strip()
                    
                    results.append({
                        'file_path': file_path,
                        'search_string': search_string,
                        'match_position': start,
                        'context': context,
                        'archive_depth': archive_depth
                    })
            
        except Exception as e:
            self.logger.error(f"Error reading or searching file {file_path}: {e}")
        return results

    def _search_in_archive(self, archive_path: str, search_strings: List[str], 
                           context_chars: int, use_regex: bool, archive_depth: int, processed_archives: set = None) -> List[Dict[str, Any]]:
        results = []
        if processed_archives is None:
            processed_archives = set()
        
        from revelare.utils.file_extractor import TemporaryDirectory_in_script_dir
        with TemporaryDirectory_in_script_dir(prefix="revelare_string_search_") as temp_dir:
            try:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_results = self._search_in_item(file_path, search_strings, context_chars, use_regex, archive_depth + 1, processed_archives)
                        for result in file_results:
                            result['file_path'] = f"{os.path.basename(archive_path)}::{os.path.relpath(file_path, temp_dir)}"
                        results.extend(file_results)
            except Exception as e:
                self.logger.error(f"Error processing archive {archive_path}: {e}")
        return results

    def save_results_to_csv(self, results: List[Dict[str, Any]], output_file: str):
        if not results:
            self.logger.warning("No results to save.")
            return
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['file_path', 'search_string', 'match_position', 'context'])
                writer.writeheader()
                for result in results:
                    writer.writerow({k: v for k, v in result.items() if k in writer.fieldnames})
            self.logger.info(f"Results saved to {output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results to {output_file}: {e}")
    
    def _read_file_safely(self, file_path: str) -> str:
        encodings = ['utf-8', 'latin-1', 'cp1252']
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    return f.read()
            except (UnicodeDecodeError, IOError):
                continue
        self.logger.warning(f"Could not read {file_path} as text.")
        return ""
    
    def _is_archive_file(self, file_path: str) -> bool:
        return file_path.lower().endswith('.zip')