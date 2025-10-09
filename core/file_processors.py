#!/usr/bin/env python3
"""
File Processing Module for Project Revelare
Contains functions for processing different types of files and extracting indicators.
"""

import os
import re
import tempfile
import zipfile
from typing import Dict, List, Any, Optional
from pathlib import Path
from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.core.validators import DataValidator
from revelare.core.enrichers import DataEnricher
from revelare.utils.data_enhancer import DataEnhancer, EnhancedIndicator

logger = get_logger(__name__)
enhancer = DataEnhancer()


class FileProcessor:
    """Base class for file processing operations."""

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process a file and return extracted indicators."""
        raise NotImplementedError("Subclasses must implement process_file method")


class TextFileProcessor(FileProcessor):
    """Processor for text-based files."""

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process text file and extract indicators."""
        try:
            # Validate input parameters
            if not file_path or not isinstance(file_path, str):
                self.logger.error("Invalid file_path provided to TextFileProcessor")
                return {}

            if not file_name or not isinstance(file_name, str):
                self.logger.error("Invalid file_name provided to TextFileProcessor")
                return {}

            # Attempt to read file with different encodings
            content = None
            encodings_to_try = ['utf-8', 'utf-16', 'latin-1', 'cp1252']

            for encoding in encodings_to_try:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    break
                except (UnicodeDecodeError, IOError) as e:
                    self.logger.debug(f"Failed to read {file_name} with {encoding}: {e}")
                    continue

            if content is None:
                self.logger.error(f"Could not read file {file_name} with any supported encoding")
                return {}

            if not content.strip():
                self.logger.warning(f"Empty file: {file_name}")
                return {}

            return self._find_matches_in_text(content, file_name)

        except PermissionError:
            self.logger.error(f"Permission denied reading file: {file_path}")
            return {}
        except FileNotFoundError:
            self.logger.error(f"File not found: {file_path}")
            return {}
        except IsADirectoryError:
            self.logger.error(f"Path is a directory, not a file: {file_path}")
            return {}
        except OSError as e:
            self.logger.error(f"OS error reading file {file_path}: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Unexpected error processing text file {file_path}: {e}")
            return {}

    def _find_matches_in_text(self, text: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Find regex matches in text content."""
        from revelare.config.config import Config
        NOISY_INDICATORS = Config.NOISY_INDICATORS
        findings = {}

        if not text or not isinstance(text, str):
            self.logger.warning(f"Invalid text type for {file_name}")
            return findings

        # Limit text size for performance
        max_text_size = getattr(Config, 'MAX_TEXT_SIZE_FOR_PROCESSING', 50 * 1024 * 1024)  # 50MB default
        if len(text) > max_text_size:
            self.logger.warning(f"Text too large for {file_name} ({len(text)} bytes), truncating")
            text = text[:max_text_size]

        # Cache compiled patterns to avoid recompiling on every call
        if not hasattr(self, '_compiled_patterns_cache'):
            self._compiled_patterns_cache = {}
            for category, pattern in Config.REGEX_PATTERNS.items():
                if category in NOISY_INDICATORS:
                    continue
                try:
                    self._compiled_patterns_cache[category] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error as e:
                    self.logger.error(f"Invalid regex pattern for {category}: {e}")
                    continue

        compiled_patterns = self._compiled_patterns_cache

        # Process each regex pattern
        for category, compiled_pattern in compiled_patterns.items():
            try:
                matches = compiled_pattern.finditer(text)
                match_count = 0
                seen_indicators = set()

                for match in matches:
                    try:
                        indicator = match.group(0).strip()
                        if not indicator or indicator in seen_indicators:
                            continue
                        seen_indicators.add(indicator)
                    except Exception as e:
                        self.logger.warning(f"Error processing individual match in {category} for {file_name}: {e}")
                        continue

                    # Create enhanced indicator
                    enhanced = enhancer.create_enhanced_indicator(
                        indicator=indicator,
                        category=category,
                        context=text[max(0, match.start()-100):match.end()+100],
                        file_name=file_name,
                        position=match.start()
                    )

                    # Filter out irrelevant indicators
                    if enhancer.is_irrelevant(enhanced):
                        continue

                    # Additional validation for specific categories
                    if category == 'Email_Addresses' and not DataValidator.is_valid_email(indicator):
                        continue
                    elif category == 'Phone_Numbers' and not DataValidator.is_valid_phone(indicator):
                        continue
                    elif category == 'SSN' and not DataValidator.is_valid_ssn(indicator):
                        continue
                    elif category == 'SSN_with_dots' and not DataValidator.is_valid_ssn(indicator.replace('.', '-')):
                        continue
                    elif category == 'US_Zip_Codes' and not self._is_valid_zip_code(indicator):
                        continue
                    elif category == 'Credit_Card_Numbers' and not self._is_valid_credit_card(indicator):
                        continue
                    elif category == 'VIN' and not self._is_valid_vin(indicator):
                        continue
                    elif category == 'Routing_Numbers' and not DataValidator.is_valid_routing_number(indicator):
                        continue

                    # Store the enhanced indicator
                    findings.setdefault(category, {})

                    # Create context string with enhanced metadata
                    context_parts = []
                    if enhanced.timestamp:
                        context_parts.append(f"Timestamp: {enhanced.timestamp}")
                    if enhanced.source_port:
                        context_parts.append(f"Source Port: {enhanced.source_port}")
                    if enhanced.destination_port:
                        context_parts.append(f"Destination Port: {enhanced.destination_port}")
                    if enhanced.protocol:
                        context_parts.append(f"Protocol: {enhanced.protocol}")
                    if enhanced.user_agent:
                        context_parts.append(f"User-Agent: {enhanced.user_agent}")
                    if enhanced.session_id:
                        context_parts.append(f"Session-ID: {enhanced.session_id}")

                    context_parts.append(f"File: {file_name}")
                    context_parts.append(f"Position: {enhanced.position}")

                    context = " | ".join(context_parts)

                    # For IPs, add classification
                    if "IP" in category:
                        ip_type = DataValidator.classify_ip(indicator)
                        context += f" | Type: {ip_type}"

                    # For phone numbers, add area code enrichment
                    if category == 'Phone_Numbers':
                        area_code = indicator[:3] if len(indicator) >= 3 else indicator
                        enriched_area = DataEnricher.enrich_area_code(area_code)
                        if 'error' not in enriched_area:
                            context += f" | Location: {enriched_area.get('city', 'Unknown')}, {enriched_area.get('state', 'Unknown')} | Timezone: {enriched_area.get('timezone', 'Unknown')}"
                        else:
                            context += f" | Area Code: {area_code} (enrichment failed)"

                    findings[category][indicator] = context
                    match_count += 1

                if match_count > 0:
                    self.logger.debug(f"Found {match_count} matches for {category} in {file_name}")

            except Exception as e:
                self.logger.warning(f"Error processing pattern {category} for {file_name}: {e}")
                continue

        return findings

    def _is_valid_zip_code(self, zip_code: str) -> bool:
        """Validate US zip code format."""
        if not zip_code:
            return False

        # Remove any dashes for validation
        cleaned = zip_code.replace('-', '')

        # Must be 5 or 9 digits
        if len(cleaned) not in [5, 9] or not cleaned.isdigit():
            return False

        # Basic US zip code validation
        # First digit should not be 0 (except for some territories)
        if len(cleaned) == 5 and cleaned[0] == '0':
            # Allow some valid 0-starting zips (territories, etc.)
            valid_zero_zips = ['00601', '00602', '00603', '00604', '00605']  # PR examples
            if cleaned not in valid_zero_zips:
                return False

        return True

    def _is_valid_credit_card(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        if not card_number:
            return False

        # Remove spaces and dashes
        cleaned = re.sub(r'[^\d]', '', card_number)

        if len(cleaned) < 13 or len(cleaned) > 19:
            return False

        # Luhn algorithm
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10

        return luhn_checksum(cleaned) == 0


    def _is_valid_vin(self, vin: str) -> bool:
        """Validate Vehicle Identification Number."""
        if not vin or len(vin) != 17:
            return False

        # VIN should only contain valid characters (no I, O, Q)
        if not re.match(r'^[A-HJ-NPR-Z0-9]{17}$', vin):
            return False

        # Basic checksum validation (simplified)
        # This is a complex algorithm, but for now we'll do basic validation
        # A full VIN validation would require the complete ISO 3779-1983 algorithm
        return True  # Simplified - accepts format-valid VINs


class EmailFileProcessor(FileProcessor):
    """Processor for email files."""

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process email file and extract indicators."""
        file_ext = os.path.splitext(file_path)[1].lower()
        findings = {}

        if file_ext == '.eml' or file_ext in ['.mbox', '.mbx']:
            return TextFileProcessor().process_file(file_path, file_name)

        elif file_ext == '.msg':
            try:
                import extract_msg
                with extract_msg.Message(file_path) as msg:
                     email_content = f"From: {msg.sender}\nTo: {msg.to}\nSubject: {msg.subject}\nBody:\n{msg.body}"
                     findings = TextFileProcessor()._find_matches_in_text(email_content, file_name)
            except ImportError:
                self.logger.warning("`extract-msg` not available. Treating .msg as binary file.")
                findings = BinaryFileProcessor().process_file(file_path, file_name)
            except Exception as e:
                 self.logger.warning(f"Error processing .msg file: {e}, treating as binary")
                 findings = BinaryFileProcessor().process_file(file_path, file_name)

        elif file_ext in ['.pst', '.ost']:
            findings = BinaryFileProcessor().process_file(file_path, file_name)

        else:
            findings = BinaryFileProcessor().process_file(file_path, file_name)

        self.logger.info(f"Email file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings


class DocumentFileProcessor(FileProcessor):
    """Processor for document files."""

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process document file and extract indicators."""
        file_ext = os.path.splitext(file_path)[1].lower()
        findings = {}

        try:
            content = ""
            if file_ext == '.pdf':
                import pypdf
                from PIL import Image
                import io

                content = ""
                with open(file_path, 'rb') as f:
                    reader = pypdf.PdfReader(f)

                    # Extract text from all pages
                    for page in reader.pages:
                        page_text = page.extract_text() or ""
                        content += page_text + "\n"

                    # Try to extract images for OCR if text extraction was poor
                    if len(content.strip()) < 100:  # If very little text was found
                        self.logger.info(f"Low text content in PDF {file_name}, attempting OCR on images")
                        try:
                            for page_num, page in enumerate(reader.pages):
                                for image_key in page.images.keys():
                                    try:
                                        image_data = page.images[image_key]
                                        image_bytes = image_data.data

                                        # Convert to PIL Image
                                        image = Image.open(io.BytesIO(image_bytes))

                                        # Perform OCR on the image
                                        media_processor = MediaFileProcessor()
                                        ocr_text = media_processor._perform_ocr_from_bytes(image_bytes, f"{file_name}_page_{page_num}_{image_key}")
                                        if ocr_text:
                                            content += f"\n[OCR from image {image_key} on page {page_num + 1}]\n{ocr_text}\n"
                                    except Exception as img_error:
                                        self.logger.debug(f"Could not OCR image {image_key} on page {page_num}: {img_error}")
                                        continue
                        except Exception as ocr_error:
                            self.logger.debug(f"Could not perform OCR on PDF images: {ocr_error}")

                content = content.strip()

            elif file_ext in ['.docx', '.doc']:
                from docx import Document
                doc = Document(file_path)
                content = "\n".join(paragraph.text for paragraph in doc.paragraphs)

            elif file_ext in ['.xlsx', '.xls']:
                import pandas as pd
                df_dict = pd.read_excel(file_path, sheet_name=None)
                for sheet_name, sheet_df in df_dict.items():
                    content += f"Sheet: {sheet_name}\n"
                    content += sheet_df.to_string() + "\n\n"

            else:
                raise ImportError(f"Unsupported document extension: {file_ext}")

            findings = TextFileProcessor()._find_matches_in_text(content, file_name)

        except ImportError as e:
            self.logger.warning(f"Library not available for {file_ext}: {e}. Treating as binary file.")
            findings = BinaryFileProcessor().process_file(file_path, file_name)
        except Exception as e:
            self.logger.warning(f"Error processing document {file_ext}: {e}. Treating as binary.")
            findings = BinaryFileProcessor().process_file(file_path, file_name)

        self.logger.info(f"Document file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings


class BinaryFileProcessor(FileProcessor):
    """Processor for binary files."""

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process binary file by extracting readable text chunks."""
        from revelare.config.config import Config
        file_size = os.path.getsize(file_path)
        BINARY_CHUNK_SIZE = Config.BINARY_CHUNK_SIZE

        # For very large files, use larger chunks and limit processing
        if file_size > Config.LARGE_FILE_THRESHOLD_MB * 1024 * 1024:
            BINARY_CHUNK_SIZE = min(Config.MAX_CHUNK_SIZE_MB * 1024 * 1024, BINARY_CHUNK_SIZE * 4)
            max_chunks = 100  # Limit chunks for large files
            self.logger.info(f"Large binary file {file_name} ({file_size} bytes), using chunk size {BINARY_CHUNK_SIZE}")
        else:
            max_chunks = float('inf')  # No limit for smaller files

        findings = {}

        try:
            with open(file_path, 'rb') as f:
                chunk_number = 0
                overlap = Config.CHUNK_OVERLAP_SIZE if Config.CHUNK_OVERLAP_SIZE < BINARY_CHUNK_SIZE else 0
                previous_chunk_end = b""

                while chunk_number < max_chunks:
                    chunk = f.read(BINARY_CHUNK_SIZE)
                    if not chunk:
                        break
                    chunk_number += 1

                    # Add overlap from previous chunk to catch split indicators
                    if overlap and previous_chunk_end:
                        chunk = previous_chunk_end[-overlap:] + chunk

                    try:
                        text_chunk = chunk.decode('utf-8', errors='ignore')
                        text_chunk = ''.join(char for char in text_chunk if char.isprintable() or char.isspace())

                        if text_chunk.strip():
                            chunk_findings = TextFileProcessor()._find_matches_in_text(text_chunk, f"{file_name}_chunk_{chunk_number}")
                            for category, items in chunk_findings.items():
                                findings.setdefault(category, {}).update(items)

                        # Store end of chunk for overlap
                        if overlap:
                            previous_chunk_end = chunk

                    except Exception as e:
                        self.logger.debug(f"Error processing binary chunk {chunk_number}: {e}")
                        continue

                    # Progress logging for large files
                    if chunk_number % 100 == 0:
                        self.logger.debug(f"Processed {chunk_number} chunks of binary file {file_name}")
        except Exception as e:
            self.logger.error(f"Error processing binary file {file_path}: {e}")
            return {}

        self.logger.info(f"Binary file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings


class ArchiveFileProcessor(FileProcessor):
    """Processor for archive files."""

    def __init__(self):
        super().__init__()
        self.max_depth = 3  # Maximum nesting depth for archives

    def estimate_processing_time(self, archive_path: str) -> Dict[str, Any]:
        """Estimate processing time and provide warnings for large archives."""
        try:
            from revelare.config.config import Config
            import zipfile

            with zipfile.ZipFile(archive_path, 'r') as zip_file:
                file_list = zip_file.namelist()
                total_files = len(file_list)
                total_size_bytes = sum(zip_file.getinfo(f).file_size for f in file_list if not f.endswith('/'))

                # Convert to MB for calculations
                total_size_mb = total_size_bytes / (1024 * 1024)

                # Categorize files by type for better time estimation
                file_types = {}
                for file_name in file_list:
                    if file_name.endswith('/'):
                        continue

                    ext = file_name.lower().split('.')[-1] if '.' in file_name else 'unknown'

                    if ext in ['txt', 'csv', 'json', 'xml', 'html', 'log']:
                        file_types['text'] = file_types.get('text', 0) + 1
                    elif ext in ['zip', 'rar', '7z', 'tar', 'gz']:
                        file_types['archive'] = file_types.get('archive', 0) + 1
                    elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff']:
                        file_types['image'] = file_types.get('image', 0) + 1
                    elif ext in ['pdf']:
                        file_types['pdf'] = file_types.get('pdf', 0) + 1
                    else:
                        file_types['binary'] = file_types.get('binary', 0) + 1

                # Calculate estimated time
                estimated_seconds = 0
                for file_type, count in file_types.items():
                    rate_per_mb = Config.PROCESSING_RATES.get(file_type, Config.PROCESSING_RATES['unknown'])
                    # Estimate average file size per type (rough approximation)
                    avg_size_mb = total_size_mb / max(total_files, 1)
                    estimated_seconds += (count * avg_size_mb * rate_per_mb)

                # Add overhead for archive operations
                estimated_seconds += (total_files * 0.01)  # 0.01 seconds per file for overhead

                # Convert to readable format
                if estimated_seconds < 60:
                    time_str = f"{estimated_seconds:.1f} seconds"
                elif estimated_seconds < 3600:
                    time_str = f"{estimated_seconds/60:.1f} minutes"
                else:
                    time_str = f"{estimated_seconds/3600:.1f} hours"

                # Determine warning level
                warning_level = "normal"
                warning_message = ""

                if total_files >= Config.HUGE_ARCHIVE_THRESHOLD:
                    warning_level = "huge"
                    warning_message = f"This is a very large archive with {total_files} files. Processing may take {time_str}. Consider processing in smaller batches."
                elif total_files >= Config.LARGE_ARCHIVE_THRESHOLD:
                    warning_level = "large"
                    warning_message = f"This is a large archive with {total_files} files. Estimated processing time: {time_str}."
                elif estimated_seconds > 300:  # 5 minutes
                    warning_level = "slow"
                    warning_message = f"This archive may take {time_str} to process due to its size/complexity."

                return {
                    'total_files': total_files,
                    'total_size_mb': total_size_mb,
                    'estimated_seconds': estimated_seconds,
                    'time_string': time_str,
                    'warning_level': warning_level,
                    'warning_message': warning_message,
                    'file_types': file_types,
                    'recommended_batch_size': min(Config.ARCHIVE_BATCH_SIZE, max(10, total_files // 10))
                }

        except Exception as e:
            self.logger.error(f"Error estimating processing time for {archive_path}: {e}")
            return {
                'total_files': 0,
                'total_size_mb': 0,
                'estimated_seconds': 0,
                'time_string': "unknown",
                'warning_level': "error",
                'warning_message': f"Could not estimate processing time: {str(e)}",
                'file_types': {},
                'recommended_batch_size': Config.ARCHIVE_BATCH_SIZE
            }

    def process_file(self, file_path: str, file_name: str, depth: int = 0, batch_callback=None) -> Dict[str, Dict[str, str]]:
        """Process archive file and recursively process contents with intelligent batching."""
        findings = {}

        try:
            import zipfile
            import tempfile
            from revelare.config.config import Config

            # Security check for archive depth
            if depth > self.max_depth:
                self.logger.warning(f"Archive depth limit reached for {file_name}")
                return findings

            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Get list of files in the archive
                file_list = zip_file.namelist()
                total_files = len([f for f in file_list if not f.endswith('/')])  # Exclude directories

                self.logger.info(f"Processing archive {file_name} with {total_files} files")

                # Get processing estimate for user feedback
                estimate = self.estimate_processing_time(file_path)
                if estimate['warning_message']:
                    self.logger.warning(estimate['warning_message'])

                # Use recommended batch size or process all at once for smaller archives
                batch_size = estimate['recommended_batch_size'] if total_files > Config.LARGE_ARCHIVE_THRESHOLD else total_files
                batches = []

                # Create batches of files to process
                files_to_process = [f for f in file_list if not f.endswith('/')]
                for i in range(0, len(files_to_process), batch_size):
                    batches.append(files_to_process[i:i + batch_size])

                self.logger.info(f"Processing {file_name} in {len(batches)} batch(es) of up to {batch_size} files each")

                processed_count = 0
                batch_number = 0

                # Process files in batches
                for batch in batches:
                    batch_number += 1
                    batch_findings = {}

                    if len(batches) > 1:
                        self.logger.info(f"Processing batch {batch_number}/{len(batches)} ({len(batch)} files)")

                    # Process each file in the current batch
                    for file_index, zip_file_name in enumerate(batch):
                        try:
                            # Skip directories
                            if zip_file_name.endswith('/'):
                                continue

                            # Security check for path traversal
                            if '..' in zip_file_name or os.path.isabs(zip_file_name):
                                self.logger.warning(f"Skipping potentially dangerous file path in archive: {zip_file_name}")
                                continue

                            # Check file size in archive
                            try:
                                file_info = zip_file.getinfo(zip_file_name)
                                if file_info.file_size > Config.MAX_FILE_SIZE_IN_ARCHIVE:
                                    self.logger.warning(f"File {zip_file_name} in archive too large ({file_info.file_size} bytes), skipping")
                                    continue
                            except:
                                # If we can't get file info, proceed cautiously
                                pass

                            # Extract file to temporary location
                            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(zip_file_name)[1]) as temp_file:
                                temp_file.write(zip_file.read(zip_file_name))
                                temp_file_path = temp_file.name

                            try:
                                # Process the extracted file
                                file_findings = self._process_extracted_file(temp_file_path, zip_file_name, depth + 1)

                                # Merge findings from this file into batch findings
                                for category, items in file_findings.items():
                                    batch_findings.setdefault(category, {}).update(items)

                                processed_count += 1

                                # Progress callback for UI updates
                                if batch_callback and processed_count % 10 == 0:
                                    progress = (processed_count / total_files) * 100
                                    batch_callback(f"Processed {processed_count}/{total_files} files ({progress:.1f}%)")

                            finally:
                                # Clean up temporary file
                                try:
                                    os.unlink(temp_file_path)
                                except:
                                    pass

                        except Exception as e:
                            self.logger.error(f"Error processing file {zip_file_name} in archive {file_name}: {e}")
                            continue

                    # Merge batch findings into main findings
                    for category, items in batch_findings.items():
                        findings.setdefault(category, {}).update(items)

                    # Log batch completion
                    if len(batches) > 1:
                        batch_files_processed = len(batch)
                        self.logger.info(f"Completed batch {batch_number}/{len(batches)}: {batch_files_processed} files processed")

                    # Optional: Allow for batch pause/resume logic here
                    # if batch_callback and some_pause_condition:
                    #     batch_callback("paused")
                    #     # Wait for resume signal

        except Exception as e:
            self.logger.error(f"Error processing archive file {file_path}: {e}")
            return findings

        self.logger.info(f"Archive file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings

    def _process_extracted_file(self, file_path: str, file_name: str, depth: int) -> Dict[str, Dict[str, str]]:
        """Process an extracted file based on its type."""
        try:
            file_ext = os.path.splitext(file_path)[1].lower()

            # Determine file type and process accordingly
            if file_ext in ['.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm']:
                return TextFileProcessor().process_file(file_path, file_name)
            elif file_ext in ['.eml', '.msg', '.mbox', '.mbx']:
                return EmailFileProcessor().process_file(file_path, file_name)
            elif file_ext in ['.pdf', '.docx', '.doc', '.xlsx', '.xls']:
                return DocumentFileProcessor().process_file(file_path, file_name)
            elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                return self.process_file(file_path, file_name, depth)
            else:
                # Try binary processing for unknown file types
                return BinaryFileProcessor().process_file(file_path, file_name)

        except Exception as e:
            self.logger.error(f"Error processing extracted file {file_path}: {e}")
            return {}


class MediaFileProcessor(FileProcessor):
    """Processor for media files with OCR and transcription capabilities."""

    def __init__(self):
        super().__init__()
        self.ocr_available = False
        self.whisper_available = False
        self.speech_recognition_available = False

        # Check for OCR capability
        try:
            import pytesseract
            pytesseract.get_tesseract_version()
            self.ocr_available = True
            self.logger.info("Tesseract OCR is available")
        except (ImportError, Exception) as e:
            self.logger.warning(f"Tesseract OCR not available: {e}")

        # Check for Whisper transcription
        try:
            import whisper
            self.whisper_available = True
            self.logger.info("OpenAI Whisper is available for transcription")
        except ImportError:
            self.logger.warning("OpenAI Whisper not available for transcription")

        # Check for speech recognition (fallback)
        try:
            import speech_recognition as sr
            self.speech_recognition_available = True
            self.logger.info("Speech Recognition is available as fallback")
        except ImportError:
            self.logger.warning("Speech Recognition not available as fallback")

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process media file with OCR/transcription capabilities."""
        try:
            findings = {}
            file_ext = os.path.splitext(file_path)[1].lower()

            # Extract basic metadata
            try:
                stat = os.stat(file_path)
                metadata = f"File: {file_name}\nSize: {stat.st_size} bytes\nCreated: {stat.st_ctime}\nModified: {stat.st_mtime}\nPath: {file_path}"
                metadata_findings = TextFileProcessor()._find_matches_in_text(metadata, file_name)
                findings.update(metadata_findings)
            except Exception as e:
                self.logger.warning(f"Error extracting metadata from {file_name}: {e}")

            # Process images with OCR
            if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp']:
                ocr_text = self._perform_ocr(file_path, file_name)
                if ocr_text:
                    ocr_findings = TextFileProcessor()._find_matches_in_text(ocr_text, file_name)
                    findings.update(ocr_findings)
                    self.logger.info(f"OCR extracted {len(ocr_text)} characters from {file_name}")

            # Process audio/video files with transcription
            elif file_ext in ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.aiff', '.mp4', '.avi', '.mkv', '.mov', '.wmv']:
                transcript = self._perform_transcription(file_path, file_name)
                if transcript:
                    transcript_findings = TextFileProcessor()._find_matches_in_text(transcript, file_name)
                    findings.update(transcript_findings)
                    self.logger.info(f"Transcription extracted {len(transcript)} characters from {file_name}")

            # Extract additional media metadata
            try:
                import mutagen
                try:
                    audio = mutagen.File(file_path)
                    if audio and hasattr(audio, 'info'):
                        media_metadata = f"Duration: {getattr(audio.info, 'length', 'Unknown')} seconds\n"
                        media_metadata += f"Bitrate: {getattr(audio.info, 'bitrate', 'Unknown')} bps\n"
                        media_metadata += f"Sample Rate: {getattr(audio.info, 'sample_rate', 'Unknown')} Hz\n"
                        if hasattr(audio, 'tags') and audio.tags:
                            for key, value in audio.tags.items():
                                media_metadata += f"{key}: {value}\n"

                        media_findings = TextFileProcessor()._find_matches_in_text(media_metadata, file_name)
                        findings.update(media_findings)
                except Exception as e:
                    self.logger.debug(f"Could not extract advanced metadata from {file_name}: {e}")
            except ImportError:
                self.logger.debug("Mutagen not available for advanced media metadata")

            total_indicators = sum(len(items) for items in findings.values())
            self.logger.info(f"Media file {file_name} processed: {total_indicators} indicators found")
            return findings

        except Exception as e:
            self.logger.error(f"Error processing media file {file_path}: {e}")
            return {}

    def _perform_ocr(self, file_path: str, file_name: str) -> str:
        """Perform OCR on image file."""
        if not self.ocr_available:
            self.logger.debug(f"OCR not available for {file_name}")
            return ""

        try:
            import pytesseract
            from PIL import Image
            import cv2

            # Try to read image
            try:
                # First try with PIL
                image = Image.open(file_path)
                # Convert to RGB if necessary
                if image.mode not in ('L', 'RGB'):
                    image = image.convert('RGB')
                text = pytesseract.image_to_string(image)
            except Exception:
                # Fallback to OpenCV
                try:
                    image = cv2.imread(file_path)
                    if image is not None:
                        # Convert to grayscale for better OCR
                        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                        text = pytesseract.image_to_string(gray)
                    else:
                        return ""
                except Exception:
                    return ""

            return text.strip()

        except Exception as e:
            self.logger.warning(f"OCR failed for {file_name}: {e}")
            return ""

    def _perform_ocr_from_bytes(self, image_bytes: bytes, image_name: str) -> str:
        """Perform OCR on image bytes."""
        if not self.ocr_available:
            return ""

        try:
            import pytesseract
            from PIL import Image
            import cv2
            import numpy as np
            import io

            # Convert bytes to PIL Image
            try:
                image = Image.open(io.BytesIO(image_bytes))

                # Convert to RGB if necessary
                if image.mode not in ('L', 'RGB'):
                    image = image.convert('RGB')

                # Convert PIL to numpy array for OpenCV processing
                image_array = np.array(image)

                # Convert to grayscale for better OCR
                if len(image_array.shape) == 3:
                    gray = cv2.cvtColor(image_array, cv2.COLOR_RGB2GRAY)
                else:
                    gray = image_array

                # Apply some preprocessing for better OCR
                # Increase contrast
                gray = cv2.convertScaleAbs(gray, alpha=1.5, beta=0)

                # Apply threshold to get better text
                _, threshold = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

                text = pytesseract.image_to_string(threshold)

            except Exception as e:
                self.logger.debug(f"PIL/OpenCV OCR failed for {image_name}: {e}")
                return ""

            return text.strip()

        except Exception as e:
            self.logger.warning(f"OCR from bytes failed for {image_name}: {e}")
            return ""

    def _perform_transcription(self, file_path: str, file_name: str) -> str:
        """Perform speech-to-text transcription on audio/video file."""
        if not (self.whisper_available or self.speech_recognition_available):
            self.logger.debug(f"Transcription not available for {file_name}")
            return ""

        try:
            # Prefer Whisper for better accuracy
            if self.whisper_available:
                return self._transcribe_with_whisper(file_path, file_name)
            elif self.speech_recognition_available:
                return self._transcribe_with_speech_recognition(file_path, file_name)

        except Exception as e:
            self.logger.warning(f"Transcription failed for {file_name}: {e}")
            return ""

    def _transcribe_with_whisper(self, file_path: str, file_name: str) -> str:
        """Transcribe using OpenAI Whisper."""
        try:
            import whisper
            import torch

            # Load model (use base model for speed, can be upgraded to larger models)
            model = whisper.load_model("base")

            # Transcribe
            result = model.transcribe(file_path)

            return result["text"].strip()

        except Exception as e:
            self.logger.warning(f"Whisper transcription failed for {file_name}: {e}")
            return ""

    def _transcribe_with_speech_recognition(self, file_path: str, file_name: str) -> str:
        """Fallback transcription using speech_recognition library."""
        try:
            import speech_recognition as sr
            from pydub import AudioSegment

            # Convert audio to WAV if necessary
            file_ext = os.path.splitext(file_path)[1].lower()

            if file_ext not in ['.wav']:
                # Convert to WAV using pydub
                audio = AudioSegment.from_file(file_path)
                wav_path = file_path.rsplit('.', 1)[0] + '_converted.wav'
                audio.export(wav_path, format='wav')
                audio_path = wav_path
            else:
                audio_path = file_path

            # Perform speech recognition
            recognizer = sr.Recognizer()
            with sr.AudioFile(audio_path) as source:
                audio_data = recognizer.record(source)
                text = recognizer.recognize_google(audio_data)

            # Clean up converted file if created
            if audio_path != file_path and os.path.exists(audio_path):
                try:
                    os.remove(audio_path)
                except:
                    pass

            return text.strip()

        except Exception as e:
            self.logger.warning(f"Speech recognition transcription failed for {file_name}: {e}")
            return ""


class DatabaseFileProcessor(FileProcessor):
    """Processor for database files."""

    def process_file(self, file_path: str, file_name: str) -> Dict[str, Dict[str, str]]:
        """Process database file."""
        file_ext = os.path.splitext(file_path)[1].lower()
        findings = {}

        if file_ext in ['.sqlite', '.sqlite3', '.db']:
            try:
                import sqlite3
                conn = sqlite3.connect(file_path)
                content = "Database content extracted successfully." # Placeholder for full extraction logic
                findings = TextFileProcessor()._find_matches_in_text(content, file_name)
                conn.close()
            except ImportError:
                self.logger.warning("sqlite3 not available. Treating database as binary.")
                findings = BinaryFileProcessor().process_file(file_path, file_name)
            except Exception as e:
                self.logger.warning(f"Error processing database: {e}. Treating as binary.")
                findings = BinaryFileProcessor().process_file(file_path, file_name)
        else:
            findings = BinaryFileProcessor().process_file(file_path, file_name)

        self.logger.info(f"Data file {file_name} processed: {sum(len(items) for items in findings.values())} indicators found")
        return findings
