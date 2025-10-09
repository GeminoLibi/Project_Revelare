#!/usr/bin/env python3
"""
Refactored data extraction module for Project Revelare.
Uses modular processors for different file types.
"""

import os
import re
import time
from typing import Dict, List, Any
from urllib.parse import urlparse
from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator, InputValidator
from revelare.core.file_processors import (
    TextFileProcessor,
    EmailFileProcessor,
    DocumentFileProcessor,
    BinaryFileProcessor,
    ArchiveFileProcessor,
    MediaFileProcessor,
    DatabaseFileProcessor
)

logger = get_logger(__name__)
revelare_logger = RevelareLogger.get_logger('extractor')

def group_urls_by_domain(findings: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    """Group URLs by their domain for better organization."""
    if 'URLs' not in findings:
        return findings
    
    def extract_domain(url: str) -> str:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]
            return domain
        except:
            return "unknown"

    domain_groups = {}
    for url, context in findings['URLs'].items():
        domain = extract_domain(url)
        domain_groups.setdefault(domain, {})[url] = context

    new_findings = findings.copy()
    new_findings['URLs_by_Domain'] = domain_groups
    del new_findings['URLs'] 

    logger.info(f"Grouped {len(findings['URLs'])} URLs into {len(domain_groups)} domains")
    return new_findings

def filter_duplicate_emails(findings: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
    """Filter out duplicate email addresses that are substrings of other emails."""
    if 'Email_Addresses' not in findings:
        return findings
    
    emails = findings['Email_Addresses']
    if len(emails) <= 1:
        return findings
    
    # Sort emails by length (longest first) to check substrings properly
    sorted_emails = sorted(emails.items(), key=lambda x: len(x[0]), reverse=True)
    
    filtered_emails = {}
    removed_count = 0
    
    for email, context in sorted_emails:
        is_substring = False
        
        # Check if this email is a substring of any already processed email
        for existing_email in filtered_emails.keys():
            if email in existing_email and email != existing_email:
                is_substring = True
                removed_count += 1
                logger.debug(f"Removed duplicate email (substring): {email} (found in {existing_email})")
                break
        
        if not is_substring:
            filtered_emails[email] = context
    
    findings['Email_Addresses'] = filtered_emails
    logger.info(f"Email filtering: removed {removed_count} duplicate/substring emails, kept {len(filtered_emails)}")
    
    return findings

# --- Main Processing Function ---

def process_file(file_path: str, findings: Dict[str, Dict[str, str]]) -> bool:
    """Process a single file and add findings to the results dictionary."""
    try:
        if not file_path or not isinstance(file_path, str) or not isinstance(findings, dict):
            return False
        if not SecurityValidator.is_safe_path(file_path):
            return False
        if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
            return False
        
        file_name = os.path.basename(file_path)
        file_ext = os.path.splitext(file_path)[1].lower()

        from revelare.config.config import Config
        ALLOWED_EXTENSIONS = Config.ALLOWED_EXTENSIONS

        # Select appropriate processor based on file type
        if file_ext in ALLOWED_EXTENSIONS.get('text', []):
            processor = TextFileProcessor()
        elif file_ext in ALLOWED_EXTENSIONS.get('email', []):
            processor = EmailFileProcessor()
        elif file_ext in ALLOWED_EXTENSIONS.get('documents', []):
            processor = DocumentFileProcessor()
        elif file_ext in ALLOWED_EXTENSIONS.get('archives', []):
            processor = ArchiveFileProcessor()
        elif file_ext in ALLOWED_EXTENSIONS.get('data', []):
            processor = DatabaseFileProcessor()
        elif file_ext in ALLOWED_EXTENSIONS.get('images', []) + ALLOWED_EXTENSIONS.get('audio', []) + ALLOWED_EXTENSIONS.get('video', []):
            processor = MediaFileProcessor()
        else:
            # Default to binary processor for unknown file types
            processor = BinaryFileProcessor()

        # Process the file
        file_findings = processor.process_file(file_path, file_name)

        # Merge findings
        for category, items in file_findings.items():
            findings.setdefault(category, {}).update(items)

        logger.info(f"Successfully processed {file_name}")
        return True

    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")
        return False

# --- Main Entry and Orchestration ---

def run_extraction(input_files: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Run indicator extraction on multiple files. (Main entry point)
    """
    from revelare.config.config import Config
    PROGRESS_UPDATE_INTERVAL = Config.PROGRESS_UPDATE_INTERVAL
    MONITORING_INTERVAL_SECONDS = Config.MONITORING_INTERVAL_SECONDS 

    findings = {}
    processed_files = 0
    failed_files = 0
    skipped_files = 0

    if not input_files or not isinstance(input_files, list):
        logger.error("Invalid input_files provided")
        return findings

    logger.info(f"Starting extraction on {len(input_files)} files")
    # revelare_logger.log_performance("extraction_start", 0.0, {"file_count": len(input_files)})

    start_time = time.time()
    last_monitor_time = start_time

    for i, file_path in enumerate(input_files):
        try:
            file_name = os.path.basename(file_path)
            print(f"[HEARTBEAT] Processing file {i+1}/{len(input_files)}: {file_name}")
            
            file_start_time = time.time()
            if process_file(file_path, findings):
                processed_files += 1
                file_time = time.time() - file_start_time
                if file_time > 60: 
                    logger.info(f"File {file_name} processed in {file_time:.1f}s")
                    print(f"[HEARTBEAT] Large file completed: {file_name} in {file_time:.1f}s")
            else:
                skipped_files += 1

            current_time = time.time()
            if ((i + 1) % PROGRESS_UPDATE_INTERVAL == 0 or
                    current_time - last_monitor_time >= MONITORING_INTERVAL_SECONDS):
                elapsed = current_time - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                total_indicators = sum(len(items) for items in findings.values())
                logger.info(f"Progress: {i+1}/{len(input_files)} files processed ({rate:.1f} files/sec, {total_indicators} indicators)")
                last_monitor_time = current_time

        except Exception as e:
            logger.error(f"Failed to process {file_path}: {e}")
            failed_files += 1

    processing_time = time.time() - start_time

    # Log results
    logger.info(f"Extraction complete: {processed_files} processed, {failed_files} failed, {skipped_files} skipped")
    # revelare_logger.log_performance("extraction_complete", processing_time, {
    #     "processed_files": processed_files,
    #     "failed_files": failed_files,
    #     "skipped_files": skipped_files,
    #     "total_indicators": sum(len(items) for items in findings.values())
    # })

    # Group URLs by domain
    logger.info("Grouping URLs by domain...")
    findings = group_urls_by_domain(findings)
    
    # Filter out email addresses that are substrings of other emails
    findings = filter_duplicate_emails(findings)

    # Add processing summary to findings
    findings["Processing_Summary"] = {
        "Total_Files_Processed": str(processed_files),
        "Total_Files_Failed": str(failed_files),
        "Total_Files_Skipped": str(skipped_files),
        "Processing_Time_Seconds": str(round(processing_time, 2))
    }
    
    return findings