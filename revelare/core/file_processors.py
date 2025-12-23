import os
import re
import tempfile
import zipfile
from typing import Dict, List, Any, Optional

from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.core.validators import DataValidator
from revelare.core.enrichers import DataEnricher
from revelare.utils.data_enhancer import DataEnhancer
from revelare.utils.file_extractor import safe_extract_archive
from revelare.utils.security import SecurityValidator

logger = get_logger(__name__)
enhancer = DataEnhancer()

class FileProcessor:
    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        raise NotImplementedError

class TextFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        try:
            if not file_path or not isinstance(file_path, str):
                self.logger.error("Invalid file_path provided to TextFileProcessor")
                return {}
            if not file_name or not isinstance(file_name, str):
                self.logger.error("Invalid file_name provided to TextFileProcessor")
                return {}

            content = None
            encodings_to_try = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
            for encoding in encodings_to_try:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    break
                except Exception as e:
                    self.logger.debug(f"Failed to read {file_name} with {encoding}: {e}")
                    continue
            
            if content is None:
                self.logger.error(f"Could not read file {file_name} with any supported encoding")
                return {}

            if not content.strip():
                self.logger.warning(f"Empty file: {file_name}")
                return {}

            # Deobfuscate text before processing (handles [.], (dot), [@], (at), hxxp, etc.)
            from revelare.utils.financial_validators import deobfuscate_text
            content = deobfuscate_text(content)

            return self._find_matches_in_text(content, file_name)
        except Exception as e:
            self.logger.error(f"Unexpected error processing text file {file_path}: {e}")
            return {}

    def _find_matches_in_text(self, text: str, file_name: str) -> Dict[str, Dict[str, str]]:
        findings = {}
        if not text or not isinstance(text, str):
            self.logger.warning(f"Invalid text type for {file_name}")
            return findings

        max_text_size = getattr(Config, 'MAX_TEXT_SIZE_FOR_PROCESSING', 50 * 1024 * 1024)
        chunk_overlap = 1000  # Overlap between chunks to avoid missing indicators at boundaries
        
        if not hasattr(self, '_compiled_patterns_cache'):
            self._compiled_patterns_cache = {}
            for category, pattern in Config.REGEX_PATTERNS.items():
                try:
                    self._compiled_patterns_cache[category] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern for {category}: {e}")
                    continue
        
        compiled_patterns = self._compiled_patterns_cache
        
        # Process in chunks if file is too large
        if len(text) > max_text_size:
            self.logger.info(f"Text too large for {file_name} ({len(text)} bytes), processing in chunks")
            total_chunks = (len(text) + max_text_size - 1) // max_text_size
            chunk_num = 0
            
            for chunk_start in range(0, len(text), max_text_size - chunk_overlap):
                chunk_end = min(chunk_start + max_text_size, len(text))
                chunk_text = text[chunk_start:chunk_end]
                chunk_offset = chunk_start
                chunk_num += 1
                
                if chunk_num % 10 == 0:
                    self.logger.debug(f"Processing chunk {chunk_num}/{total_chunks} of {file_name}")
                
                # Process this chunk
                chunk_findings = self._process_text_chunk(
                    chunk_text, file_name, chunk_offset, compiled_patterns
                )
                
                # Merge findings (deduplicate by indicator value)
                for category, items in chunk_findings.items():
                    findings.setdefault(category, {}).update(items)
        else:
            # Process entire file at once
            findings = self._process_text_chunk(text, file_name, 0, compiled_patterns)
        
        return findings
    
    def _process_text_chunk(self, text: str, file_name: str, offset: int, 
                           compiled_patterns: Dict[str, re.Pattern]) -> Dict[str, Dict[str, str]]:
        """Process a chunk of text and return findings"""
        findings = {}
        
        for category, compiled_pattern in compiled_patterns.items():
            seen_indicators = set()
            try:
                for match in compiled_pattern.finditer(text):
                    indicator = match.group(0).strip()
                    if not indicator or indicator in seen_indicators:
                        continue
                    seen_indicators.add(indicator)
                    
                    # Calculate absolute position including offset
                    absolute_position = offset + match.start()

                    enhanced = enhancer.create_enhanced_indicator(
                        indicator=indicator, category=category,
                        context=text[max(0, match.start()-100):match.end()+100],
                        file_name=file_name, position=absolute_position
                    )

                    if enhancer.is_irrelevant(enhanced):
                        continue

                    context_parts = [
                        f"File: {file_name}",
                        f"Position: {absolute_position}"
                    ]
                    
                    if "IP" in category:
                        context_parts.append(f"Type: {DataValidator.classify_ip(indicator)}")
                    
                    # Validate credit cards with Luhn algorithm
                    if category in ['Credit_Card_VisaMcDiscover', 'Credit_Card_Amex', 'Credit_Card_Numbers']:
                        from revelare.utils.financial_validators import validate_and_classify_credit_card
                        validation = validate_and_classify_credit_card(indicator)
                        if not validation['is_valid_luhn']:
                            # Skip invalid credit card numbers (likely false positives)
                            continue
                        context_parts.append(f"Issuer: {validation['issuer']}")
                        context_parts.append("Luhn: Valid")
                    
                    findings.setdefault(category, {})[indicator] = " | ".join(context_parts)
            except Exception as e:
                self.logger.warning(f"Error processing pattern {category} for {file_name}: {e}")
                continue
        
        return findings

class EmailFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in ['.eml', '.mbox', '.mbx']:
            return TextFileProcessor().process_file(file_path, file_name)
        return BinaryFileProcessor().process_file(file_path, file_name)

class DocumentFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        file_ext = os.path.splitext(file_path)[1].lower()
        content = ""
        try:
            if file_ext == '.pdf':
                import pypdf
                with open(file_path, 'rb') as f:
                    reader = pypdf.PdfReader(f)
                    for page in reader.pages:
                        content += (page.extract_text() or "") + "\n"
            elif file_ext in ['.docx', '.doc']:
                from docx import Document
                doc = Document(file_path)
                content = "\n".join(p.text for p in doc.paragraphs)
            elif file_ext in ['.xlsx', '.xls']:
                import pandas as pd
                df_dict = pd.read_excel(file_path, sheet_name=None)
                for sheet_name, df in df_dict.items():
                    content += f"Sheet: {sheet_name}\n{df.to_string()}\n\n"
            else:
                return BinaryFileProcessor().process_file(file_path, file_name)
            
            return TextFileProcessor()._find_matches_in_text(content, file_name)
        except Exception as e:
            self.logger.warning(f"Error processing document {file_name}: {e}. Treating as binary.")
            return BinaryFileProcessor().process_file(file_path, file_name)

class BinaryFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        findings = {}
        try:
            with open(file_path, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk = f.read(Config.BINARY_CHUNK_SIZE)
                    if not chunk:
                        break
                    chunk_num += 1
                    try:
                        text_chunk = chunk.decode('utf-8', errors='ignore')
                        printable_chunk = ''.join(c for c in text_chunk if c.isprintable() or c.isspace())
                        if printable_chunk.strip():
                            chunk_findings = TextFileProcessor()._find_matches_in_text(printable_chunk, f"{file_name}_chunk_{chunk_num}")
                            for category, items in chunk_findings.items():
                                findings.setdefault(category, {}).update(items)
                    except Exception as e:
                        self.logger.debug(f"Error processing binary chunk {chunk_num}: {e}")
        except Exception as e:
            self.logger.error(f"Error processing binary file {file_path}: {e}")
        return findings

class ArchiveFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str, depth: int = 0, processed_archives: set = None) -> Dict[str, Dict[str, str]]:
        """
        Process archive files recursively with no depth limit.
        Uses processed_archives set to prevent infinite loops from circular references.
        """
        findings = {}
        
        if processed_archives is None:
            processed_archives = set()
        
        # Normalize path to prevent duplicate processing
        normalized_path = os.path.normpath(file_path)
        if normalized_path in processed_archives:
            self.logger.debug(f"Skipping already processed archive: {file_name}")
            return findings
        
        # processed_archives.add(normalized_path) # safe_extract_archive adds it
        
        try:
            from revelare.utils.file_extractor import TemporaryDirectory_in_script_dir
            with TemporaryDirectory_in_script_dir(prefix=f"revelare_archive_{os.path.basename(file_name)}_") as temp_dir:
                # Use the centralized safe_extract_archive which handles zip, 7z, rar, etc. recursively
                success, error = safe_extract_archive(file_path, temp_dir, depth, processed_archives)
                
                if not success:
                    self.logger.warning(f"Extraction warning for {file_name}: {error}")
                    # Continue processing whatever was extracted?
                
                # Now walk the extracted files and process them
                # Since safe_extract_archive is recursive, we just need to find non-archive files to process
                # or process everything and let the extractor dispatcher handle it (but skip redundant recursion)
                
                from revelare.core.extractor import process_file as process_extracted_file
                
                for root, dirs, files in os.walk(temp_dir):
                    for member_file in files:
                        target_path = os.path.join(root, member_file)
                        
                        if not SecurityValidator.is_safe_path(target_path, temp_dir):
                            continue
                            
                        # Check if it's an archive. If it is, safe_extract_archive likely already extracted it 
                        # to a subdir. We can skip processing the raw archive file to avoid duplication 
                        # and let the loop find the extracted contents.
                        ext = os.path.splitext(target_path)[1].lower()
                        if ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                             continue
                        
                        # Process the file (text, doc, binary, etc.)
                        process_extracted_file(target_path, findings)

        except Exception as e:
            self.logger.error(f"Error processing archive {file_name}: {e}")
        return findings

class MediaFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        findings = {}
        
        # For image files, only extract EXIF metadata - skip binary regex scanning
        # Binary scanning would find UUIDs and other patterns in embedded JSON/metadata
        # which is not useful for actual image files
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ['.jpg', '.jpeg', '.png', '.tiff', '.tif', '.webp', '.bmp', '.gif']:
            try:
                from revelare.core.metadata_extractor import MetadataExtractor
                metadata = MetadataExtractor.extract_image_metadata(file_path)
                
                if metadata:
                    # Format metadata as indicators
                    if 'GPS' in metadata:
                        findings.setdefault('GPS_Coordinates', {})[metadata['GPS']] = f"File: {file_name} | Source: EXIF | Device: {metadata.get('Model', 'Unknown')}"
                    
                    if 'DateTimeOriginal' in metadata:
                        findings.setdefault('Timestamps', {})[metadata['DateTimeOriginal']] = f"File: {file_name} | Type: EXIF Creation Date"
                    elif 'DateTime' in metadata:
                        findings.setdefault('Timestamps', {})[metadata['DateTime']] = f"File: {file_name} | Type: EXIF DateTime"
                    
                    # Store device info
                    if 'Model' in metadata:
                        device_str = f"{metadata.get('Make', '')} {metadata.get('Model', '')}".strip()
                        if device_str:
                            findings.setdefault('Device_Info', {})[device_str] = f"File: {file_name} | Source: EXIF"
                    
                    if 'Software' in metadata:
                        findings.setdefault('Software_Info', {})[metadata['Software']] = f"File: {file_name} | Source: EXIF"
                    
                    if 'Resolution' in metadata:
                        findings.setdefault('Image_Resolution', {})[metadata['Resolution']] = f"File: {file_name}"
                    
                    if 'Format' in metadata:
                        findings.setdefault('Image_Format', {})[metadata['Format']] = f"File: {file_name}"
            
            except Exception as e:
                self.logger.debug(f"Failed to extract EXIF metadata from {file_name}: {e}")
        else:
            # For non-image media files (audio, video), use binary processor
            findings = BinaryFileProcessor().process_file(file_path, file_name)
                
        return findings

class DatabaseFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        return BinaryFileProcessor().process_file(file_path, file_name)
