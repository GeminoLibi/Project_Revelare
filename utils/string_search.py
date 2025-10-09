#!/usr/bin/env python3
"""
Integrated String Search Module for Project Revelare
Integrates with the main extraction system and provides string search functionality.
"""

import os
import csv
import re
import tempfile
import zipfile
import time
from typing import List, Dict, Any, Tuple
from pathlib import Path
import logging

# Import from the main system
from revelare.config.config import Config
from revelare.utils.logger import get_logger

class StringSearchEngine:
    """String search engine that integrates with the main Revelare system."""
    
    def __init__(self, logger=None):
        self.logger = logger or get_logger(__name__)
        self.interrupted = False
    
    def search_strings_in_file(self, file_path: str, search_strings: List[str], 
                              context_chars: int = 50, archive_depth: int = 0) -> List[Dict[str, Any]]:
        """Search for strings in a single file and return matches with context."""
        results = []
        
        try:
            if not os.path.exists(file_path):
                return results
            
            # Read file with multiple encoding attempts
            content = self._read_file_safely(file_path)
            if not content:
                return results
            
            file_size = os.path.getsize(file_path)
            self.logger.debug(f"Searching in {file_path} ({file_size} bytes)")
            
            for search_string in search_strings:
                # Escape special regex characters for literal search
                escaped_string = re.escape(search_string)
                
                # Find all occurrences
                for match in re.finditer(escaped_string, content, re.IGNORECASE):
                    start_pos = match.start()
                    end_pos = match.end()
                    
                    # Calculate context boundaries
                    context_start = max(0, start_pos - context_chars)
                    context_end = min(len(content), end_pos + context_chars)
                    
                    # Extract context
                    context = content[context_start:context_end]
                    context_clean = context.replace('\n', ' ').replace('\r', ' ').strip()
                    
                    # Calculate line number
                    line_number = content[:start_pos].count('\n') + 1
                    
                    results.append({
                        'file_path': file_path,
                        'file_name': os.path.basename(file_path),
                        'search_string': search_string,
                        'match_position': start_pos,
                        'line_number': line_number,
                        'context': context_clean,
                        'context_length': len(context_clean),
                        'file_size': file_size,
                        'archive_depth': archive_depth,
                        'timestamp': time.time()
                    })
            
            self.logger.info(f"Found {len(results)} matches in {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {e}")
        
        return results
    
    def search_strings_in_archive(self, archive_path: str, search_strings: List[str], 
                                 context_chars: int = 50, archive_depth: int = 0) -> List[Dict[str, Any]]:
        """Search for strings in an archive file."""
        results = []
        
        try:
            if not archive_path.lower().endswith('.zip'):
                self.logger.warning(f"Only ZIP archives supported: {archive_path}")
                return results
            
            # Create temporary directory for extraction
            with tempfile.TemporaryDirectory(prefix=f"string_search_{archive_depth}_") as temp_dir:
                self.logger.info(f"Extracting {archive_path} to temporary directory")
                
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Search all extracted files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, temp_dir)
                        
                        # Create display path showing archive origin
                        display_path = f"{archive_path}::{relative_path}"
                        
                        file_results = self.search_strings_in_file(
                            file_path, search_strings, context_chars, archive_depth + 1
                        )
                        
                        # Update file paths to show archive origin
                        for result in file_results:
                            result['file_path'] = display_path
                            result['archive_source'] = archive_path
                            result['extracted_file'] = relative_path
                        
                        results.extend(file_results)
            
            self.logger.info(f"Archive {archive_path} processed: {len(results)} total matches found")
            
        except Exception as e:
            self.logger.error(f"Error processing archive {archive_path}: {e}")
        
        return results
    
    def search_directory(self, directory: str, search_strings: List[str], 
                        context_chars: int = 50, file_extensions: List[str] = None) -> List[Dict[str, Any]]:
        """Search for strings in files in a directory."""
        all_results = []
        
        if not os.path.exists(directory):
            self.logger.error(f"Directory does not exist: {directory}")
            return all_results
        
        # Get all files to search
        files_to_search = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                file_ext = os.path.splitext(file_path)[1].lower()
                
                # Check if file extension matches
                if not file_extensions or file_ext in file_extensions:
                    files_to_search.append(file_path)
        
        self.logger.info(f"Found {len(files_to_search)} files to search")
        
        # Process files
        for i, file_path in enumerate(files_to_search):
            if self.interrupted:
                self.logger.warning("Search interrupted by user")
                break
            
            file_size_mb = os.path.getsize(file_path) / (1024*1024) if os.path.exists(file_path) else 0
            self.logger.info(f"Processing file {i+1}/{len(files_to_search)}: {os.path.basename(file_path)} ({file_size_mb:.1f} MB)")
            
            try:
                if self._is_archive_file(file_path):
                    results = self.search_strings_in_archive(file_path, search_strings, context_chars)
                else:
                    results = self.search_strings_in_file(file_path, search_strings, context_chars)
                
                all_results.extend(results)
                
            except Exception as e:
                self.logger.error(f"Error processing {file_path}: {e}")
        
        self.logger.info(f"Search completed: {len(all_results)} total matches found")
        return all_results
    
    def save_results_to_csv(self, results: List[Dict[str, Any]], output_file: str):
        """Save search results to CSV file."""
        if not results:
            self.logger.warning("No results to save")
            return
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'file_path', 'file_name', 'search_string', 'match_position', 
                    'line_number', 'context', 'context_length', 'file_size', 
                    'archive_depth', 'archive_source', 'extracted_file', 'timestamp'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    # Ensure all fields exist with default values
                    row = {field: result.get(field, '') for field in fieldnames}
                    writer.writerow(row)
            
            self.logger.info(f"Results saved to {output_file}")
            self.logger.info(f"Total matches found: {len(results)}")
            
        except Exception as e:
            self.logger.error(f"Error saving CSV file: {e}")
    
    def _read_file_safely(self, file_path: str) -> str:
        """Safely read a file with multiple encoding attempts."""
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    return f.read()
            except Exception:
                continue
        
        self.logger.warning(f"Could not read {file_path} with any encoding")
        return ""
    
    def _is_archive_file(self, file_path: str) -> bool:
        """Check if file is an archive that can be extracted."""
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        file_ext = os.path.splitext(file_path)[1].lower()
        return file_ext in archive_extensions

# Convenience functions for backward compatibility
def search_directory(directory: str, search_strings: List[str], context_chars: int = 50, 
                    file_extensions: List[str] = None, logger: logging.Logger = None) -> List[Dict[str, Any]]:
    """Convenience function for backward compatibility."""
    engine = StringSearchEngine(logger)
    return engine.search_directory(directory, search_strings, context_chars, file_extensions)

def save_results_to_csv(results: List[Dict[str, Any]], output_file: str, logger: logging.Logger = None):
    """Convenience function for backward compatibility."""
    engine = StringSearchEngine(logger)
    engine.save_results_to_csv(results, output_file)

def setup_logging(verbose: bool = False):
    """Setup logging for the module."""
    return get_logger(__name__)

# CLI integration
def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Search for specific strings in files and return results with context in CSV format.",
        epilog="""
Examples:
  # Search for strings in files
  python string_search_integrated.py /path/to/search -s "password" "secret" -o results.csv
  
  # Search with specific file extensions
  python string_search_integrated.py /path/to/search -s "password" -e .txt .log .csv
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('directory', help='Directory to search in')
    parser.add_argument('-s', '--strings', nargs='+', help='Search strings to look for')
    parser.add_argument('-o', '--output', default=f'search_results_{int(time.time())}.csv', help='Output CSV file')
    parser.add_argument('-c', '--context', type=int, default=50, help='Context characters around match (default: 50)')
    parser.add_argument('-e', '--extensions', nargs='+', help='File extensions to search (e.g., .txt .log .csv)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose)
    
    if not args.strings:
        logger.error("No search strings provided. Use -s option.")
        return 1
    
    # Prepare file extensions
    file_extensions = []
    if args.extensions:
        file_extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in args.extensions]
    
    logger.info(f"Searching for {len(args.strings)} strings in {args.directory}")
    logger.info(f"Context size: {args.context} characters")
    logger.info(f"File extensions: {file_extensions if file_extensions else 'All files'}")
    
    # Perform search
    engine = StringSearchEngine(logger)
    results = engine.search_directory(args.directory, args.strings, args.context, file_extensions)
    
    # Save results
    engine.save_results_to_csv(results, args.output)
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
