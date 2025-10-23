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
        if len(text) > max_text_size:
            self.logger.warning(f"Text too large for {file_name} ({len(text)} bytes), truncating")
            text = text[:max_text_size]

        if not hasattr(self, '_compiled_patterns_cache'):
            self._compiled_patterns_cache = {}
            for category, pattern in Config.REGEX_PATTERNS.items():
                try:
                    self._compiled_patterns_cache[category] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern for {category}: {e}")
                    continue
        
        compiled_patterns = self._compiled_patterns_cache

        for category, compiled_pattern in compiled_patterns.items():
            seen_indicators = set()
            try:
                for match in compiled_pattern.finditer(text):
                    indicator = match.group(0).strip()
                    if not indicator or indicator in seen_indicators:
                        continue
                    seen_indicators.add(indicator)

                    enhanced = enhancer.create_enhanced_indicator(
                        indicator=indicator, category=category,
                        context=text[max(0, match.start()-100):match.end()+100],
                        file_name=file_name, position=match.start()
                    )

                    if enhancer.is_irrelevant(enhanced):
                        continue

                    context_parts = [
                        f"File: {file_name}",
                        f"Position: {enhanced.position}"
                    ]
                    
                    if "IP" in category:
                        context_parts.append(f"Type: {DataValidator.classify_ip(indicator)}")
                    
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
    def process_file(self, file_path: str, file_name: str, depth: int = 0) -> Dict[str, Dict[str, str]]:
        findings = {}
        if depth > getattr(Config, 'MAX_ZIP_DEPTH', 3):
            self.logger.warning(f"Max archive depth reached for {file_name}")
            return findings
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    for member in zip_ref.infolist():
                        if member.is_dir() or member.file_size > Config.MAX_FILE_SIZE_IN_ARCHIVE:
                            continue
                        
                        target_path = os.path.join(temp_dir, member.filename)
                        if not SecurityValidator.is_safe_path(target_path, temp_dir):
                            self.logger.warning(f"Skipping unsafe path in archive: {member.filename}")
                            continue
                        
                        zip_ref.extract(member, temp_dir)
                        
                        from revelare.core.extractor import process_file as process_extracted_file
                        process_extracted_file(target_path, findings)
                        
                        # Check if extracted file is also an archive for recursive extraction
                        if os.path.isfile(target_path):
                            file_ext = os.path.splitext(target_path)[1].lower()
                            if file_ext in ['.zip', '.rar', '.7z']:
                                # Recursively process nested archives
                                nested_findings = self.process_file(target_path, os.path.basename(target_path), depth + 1)
                                for category, items in nested_findings.items():
                                    findings.setdefault(category, {}).update(items)
        except Exception as e:
            self.logger.error(f"Error processing archive {file_name}: {e}")
        return findings

class MediaFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        return BinaryFileProcessor().process_file(file_path, file_name)

class DatabaseFileProcessor(FileProcessor):
    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        return BinaryFileProcessor().process_file(file_path, file_name)