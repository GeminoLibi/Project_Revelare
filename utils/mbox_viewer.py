#!/usr/bin/env python3
"""
Email Browser for Project Revelare
Provides functionality to view, search, and analyze various email archive formats.
Supports MBOX, Maildir, PST, and individual EML files.
Integrates with the main Revelare system for forensic analysis.
"""

import os
import re
import email
import mailbox
import json
import csv
import glob
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import argparse

from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.utils.security import SecurityValidator

logger = get_logger(__name__)

class EmailBrowser:
    """Email archive viewer and analyzer for forensic analysis."""

    def __init__(self):
        self.validator = SecurityValidator()
        self.email_patterns = {
            'from': r'^From\s+(.+?)\s+',
            'to': r'^To:\s*(.+?)$',
            'cc': r'^Cc:\s*(.+?)$',
            'bcc': r'^Bcc:\s*(.+?)$',
            'subject': r'^Subject:\s*(.+?)$',
            'date': r'^Date:\s*(.+?)$',
            'message_id': r'^Message-ID:\s*(.+?)$',
            'reply_to': r'^Reply-To:\s*(.+?)$',
            'return_path': r'^Return-Path:\s*(.+?)$'
        }

        # Supported email archive formats
        self.supported_formats = {
            'mbox': {
                'extensions': ['.mbox', '.mbx'],
                'description': 'MBOX email archive',
                'handler': self._analyze_mbox_format
            },
            'maildir': {
                'extensions': [],  # Directory-based format
                'description': 'Maildir email directory',
                'handler': self._analyze_maildir_format
            },
            'eml': {
                'extensions': ['.eml'],
                'description': 'Individual EML files',
                'handler': self._analyze_eml_files
            },
            'pst': {
                'extensions': ['.pst'],
                'description': 'Outlook PST file',
                'handler': self._analyze_pst_format
            }
        }

    def detect_email_format(self, path: str) -> Optional[str]:
        """Detect the email archive format of a given path."""
        if not os.path.exists(path):
            return None

        # Check if it's a directory (potential Maildir)
        if os.path.isdir(path):
            # Check for Maildir structure
            if (os.path.exists(os.path.join(path, 'cur')) and
                os.path.exists(os.path.join(path, 'new')) and
                os.path.exists(os.path.join(path, 'tmp'))):
                return 'maildir'
            else:
                # Check for EML files in directory
                eml_files = glob.glob(os.path.join(path, '**', '*.eml'), recursive=True)
                if eml_files:
                    return 'eml'
        else:
            # Check file extension
            _, ext = os.path.splitext(path.lower())
            for format_name, format_info in self.supported_formats.items():
                if ext in format_info['extensions']:
                    return format_name

        return None

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        if size_bytes is None or size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024.0 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        if i == 0:
            return f"{int(size_bytes)} {size_names[i]}"
        else:
            return f"{size_bytes:.2f} {size_names[i]}"

    def get_email_archives_in_case(self, case_name: str) -> List[Dict[str, Any]]:
        """Get all email archives in a case directory."""
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            evidence_dir = os.path.join(case_path, 'evidence')

            if not os.path.exists(evidence_dir):
                return []

            email_archives = []

            # Recursively search for email archives
            for root, dirs, files in os.walk(evidence_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    email_format = self.detect_email_format(file_path)
                    if email_format:
                        size_bytes = os.path.getsize(file_path)
                        email_archives.append({
                            'path': file_path,
                            'format': email_format,
                            'description': self.supported_formats[email_format]['description'],
                            'size': size_bytes,
                            'formatted_size': self._format_file_size(size_bytes),
                            'relative_path': os.path.relpath(file_path, evidence_dir)
                        })

                # Check directories for Maildir format
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    if self.detect_email_format(dir_path) == 'maildir':
                        size_bytes = sum(os.path.getsize(os.path.join(dir_path, f))
                                       for f in os.listdir(dir_path)
                                       if os.path.isfile(os.path.join(dir_path, f)))
                        email_archives.append({
                            'path': dir_path,
                            'format': 'maildir',
                            'description': self.supported_formats['maildir']['description'],
                            'size': size_bytes,
                            'formatted_size': self._format_file_size(size_bytes),
                            'relative_path': os.path.relpath(dir_path, evidence_dir)
                        })

            return email_archives

        except Exception as e:
            logger.error(f"Error scanning case {case_name} for email archives: {e}")
            return []
    
    def analyze_email_archive(self, archive_path: str) -> Dict[str, Any]:
        """Analyze an email archive of any supported format."""
        email_format = self.detect_email_format(archive_path)
        if not email_format:
            logger.error(f"Unsupported email format: {archive_path}")
            return {}

        handler = self.supported_formats[email_format]['handler']
        return handler(archive_path)

    def _analyze_mbox_format(self, mbox_path: str) -> Dict[str, Any]:
        """Analyze an MBOX file and extract metadata."""
        if not os.path.exists(mbox_path):
            logger.error(f"MBOX file not found: {mbox_path}")
            return {}
        
        # Security validation
        if not self.validator.is_safe_path(mbox_path):
            logger.error(f"Unsafe path detected: {mbox_path}")
            return {}
        
        logger.info(f"Analyzing MBOX file: {mbox_path}")
        
        try:
            mbox = mailbox.mbox(mbox_path)
            analysis = {
                'file_path': mbox_path,
                'file_name': os.path.basename(mbox_path),
                'file_size': os.path.getsize(mbox_path),
                'total_messages': len(mbox),
                'analysis_timestamp': datetime.now().isoformat(),
                'messages': [],
                'statistics': {
                    'unique_senders': set(),
                    'unique_recipients': set(),
                    'date_range': {'earliest': None, 'latest': None},
                    'subject_keywords': set(),
                    'attachment_count': 0,
                    'html_emails': 0,
                    'plain_text_emails': 0
                }
            }
            
            # Process each message
            for i, message in enumerate(mbox):
                if i % 100 == 0:
                    logger.info(f"Processing message {i+1}/{len(mbox)}")
                
                msg_data = self._extract_message_data(message, i)
                analysis['messages'].append(msg_data)
                
                # Update statistics
                self._update_statistics(analysis['statistics'], msg_data)
            
            # Convert sets to lists for JSON serialization
            analysis['statistics']['unique_senders'] = list(analysis['statistics']['unique_senders'])
            analysis['statistics']['unique_recipients'] = list(analysis['statistics']['unique_recipients'])
            analysis['statistics']['subject_keywords'] = list(analysis['statistics']['subject_keywords'])
            
            logger.info(f"MBOX analysis complete: {len(mbox)} messages processed")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing MBOX file {mbox_path}: {e}")
            return {}

    def _analyze_maildir_format(self, maildir_path: str) -> Dict[str, Any]:
        """Analyze a Maildir directory and extract metadata."""
        if not os.path.exists(maildir_path):
            logger.error(f"Maildir not found: {maildir_path}")
            return {}

        if not self.validator.is_safe_path(maildir_path):
            logger.error(f"Unsafe path detected: {maildir_path}")
            return {}

        logger.info(f"Analyzing Maildir: {maildir_path}")

        try:
            maildir = mailbox.Maildir(maildir_path)
            analysis = {
                'file_path': maildir_path,
                'file_name': os.path.basename(maildir_path),
                'file_size': sum(os.path.getsize(os.path.join(root, f))
                               for root, dirs, files in os.walk(maildir_path)
                               for f in files if os.path.isfile(os.path.join(root, f))),
                'total_messages': len(maildir),
                'analysis_timestamp': datetime.now().isoformat(),
                'format': 'maildir',
                'messages': [],
                'statistics': {
                    'unique_senders': set(),
                    'unique_recipients': set(),
                    'date_range': {'earliest': None, 'latest': None},
                    'subject_keywords': set(),
                    'attachment_count': 0,
                    'html_emails': 0,
                    'plain_text_emails': 0
                }
            }

            # Process each message
            for i, message in enumerate(maildir):
                if i % 100 == 0:
                    logger.info(f"Processing Maildir message {i+1}/{len(maildir)}")

                msg_data = self._extract_message_data(message, i)
                analysis['messages'].append(msg_data)

                # Update statistics
                self._update_statistics(analysis['statistics'], msg_data)

            # Convert sets to lists for JSON serialization
            analysis['statistics']['unique_senders'] = list(analysis['statistics']['unique_senders'])
            analysis['statistics']['unique_recipients'] = list(analysis['statistics']['unique_recipients'])
            analysis['statistics']['subject_keywords'] = list(analysis['statistics']['subject_keywords'])

            logger.info(f"Maildir analysis complete: {len(maildir)} messages processed")
            return analysis

        except Exception as e:
            logger.error(f"Error analyzing Maildir {maildir_path}: {e}")
            return {}

    def _analyze_eml_files(self, eml_path: str) -> Dict[str, Any]:
        """Analyze individual EML files in a directory."""
        if os.path.isfile(eml_path):
            # Single EML file
            eml_files = [eml_path]
        else:
            # Directory with EML files
            eml_files = glob.glob(os.path.join(eml_path, '**', '*.eml'), recursive=True)

        if not eml_files:
            logger.error(f"No EML files found: {eml_path}")
            return {}

        logger.info(f"Analyzing {len(eml_files)} EML files")

        analysis = {
            'file_path': eml_path,
            'file_name': os.path.basename(eml_path),
            'total_messages': len(eml_files),
            'analysis_timestamp': datetime.now().isoformat(),
            'format': 'eml',
            'messages': [],
            'statistics': {
                'unique_senders': set(),
                'unique_recipients': set(),
                'date_range': {'earliest': None, 'latest': None},
                'subject_keywords': set(),
                'attachment_count': 0,
                'html_emails': 0,
                'plain_text_emails': 0
            }
        }

        total_size = 0
        processed_count = 0

        for eml_file in eml_files[:1000]:  # Limit to 1000 files
            try:
                if not self.validator.is_safe_path(eml_file):
                    logger.warning(f"Skipping unsafe EML file: {eml_file}")
                    continue

                with open(eml_file, 'r', encoding='utf-8', errors='replace') as f:
                    eml_content = f.read()

                total_size += len(eml_content)

                # Parse EML content
                msg = email.message_from_string(eml_content)
                msg_data = self._extract_message_data_from_parsed(msg, processed_count, eml_file)
                analysis['messages'].append(msg_data)

                # Update statistics
                self._update_statistics(analysis['statistics'], msg_data)
                processed_count += 1

                if processed_count % 100 == 0:
                    logger.info(f"Processed {processed_count} EML files")

            except Exception as e:
                logger.warning(f"Error processing EML file {eml_file}: {e}")
                continue

        analysis['file_size'] = total_size

        # Convert sets to lists for JSON serialization
        analysis['statistics']['unique_senders'] = list(analysis['statistics']['unique_senders'])
        analysis['statistics']['unique_recipients'] = list(analysis['statistics']['unique_recipients'])
        analysis['statistics']['subject_keywords'] = list(analysis['statistics']['subject_keywords'])

        logger.info(f"EML analysis complete: {processed_count} files processed")
        return analysis

    def _analyze_pst_format(self, pst_path: str) -> Dict[str, Any]:
        """Analyze an Outlook PST file. (Note: Requires pypff library)"""
        logger.warning(f"PST analysis not implemented yet: {pst_path}")
        return {
            'file_path': pst_path,
            'file_name': os.path.basename(pst_path),
            'file_size': os.path.getsize(pst_path) if os.path.exists(pst_path) else 0,
            'format': 'pst',
            'error': 'PST analysis requires additional libraries (pypff)',
            'analysis_timestamp': datetime.now().isoformat(),
            'messages': [],
            'statistics': {}
        }

    def _extract_message_data_from_parsed(self, msg, index: int, file_path: str = "") -> Dict[str, Any]:
        """Extract data from a parsed email message."""
        msg_data = {
            'message_index': index,
            'message_id': msg.get('Message-ID', ''),
            'from': msg.get('From', ''),
            'to': msg.get('To', ''),
            'cc': msg.get('Cc', ''),
            'bcc': msg.get('Bcc', ''),
            'subject': msg.get('Subject', ''),
            'date': msg.get('Date', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'content_type': msg.get_content_type(),
            'file_path': file_path
        }

        # Extract body content
        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))

                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    try:
                        body_plain += part.get_payload(decode=True).decode('utf-8', errors='replace')
                    except:
                        body_plain += str(part.get_payload())

                elif content_type == 'text/html' and 'attachment' not in content_disposition:
                    try:
                        body_html += part.get_payload(decode=True).decode('utf-8', errors='replace')
                    except:
                        body_html += str(part.get_payload())

                elif 'attachment' in content_disposition or part.get_filename():
                    filename = part.get_filename() or f"attachment_{len(attachments)}"
                    attachments.append({
                        'filename': filename,
                        'content_type': content_type,
                        'size': len(part.get_payload())
                    })
        else:
            try:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    payload = payload.decode('utf-8', errors='replace')
                if msg.get_content_type() == 'text/html':
                    body_html = payload
                else:
                    body_plain = payload
            except:
                body_plain = str(msg.get_payload())

        msg_data.update({
            'body_plain': body_plain[:5000],  # Limit body content
            'body_html': body_html[:5000],
            'attachments': attachments,
            'attachment_count': len(attachments)
        })

        return msg_data

    def _extract_message_data(self, message: mailbox.mboxMessage, index: int) -> Dict[str, Any]:
        """Extract data from a single email message."""
        msg_data = {
            'message_index': index,
            'message_id': message.get('Message-ID', ''),
            'from': message.get('From', ''),
            'to': message.get('To', ''),
            'cc': message.get('Cc', ''),
            'bcc': message.get('Bcc', ''),
            'subject': message.get('Subject', ''),
            'date': message.get('Date', ''),
            'reply_to': message.get('Reply-To', ''),
            'return_path': message.get('Return-Path', ''),
            'content_type': message.get_content_type(),
            'content_disposition': message.get('Content-Disposition', ''),
            'has_attachments': False,
            'attachments': [],
            'body_text': '',
            'body_html': '',
            'headers': dict(message.items()),
            'size_bytes': len(str(message))
        }
        
        # Extract body content
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                content_disposition = part.get('Content-Disposition', '')
                
                if 'attachment' in content_disposition:
                    msg_data['has_attachments'] = True
                    attachment_info = {
                        'filename': part.get_filename() or 'unknown',
                        'content_type': content_type,
                        'size': len(part.get_payload(decode=True) or b'')
                    }
                    msg_data['attachments'].append(attachment_info)
                elif content_type == 'text/plain':
                    msg_data['body_text'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                elif content_type == 'text/html':
                    msg_data['body_html'] = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            content_type = message.get_content_type()
            if content_type == 'text/plain':
                msg_data['body_text'] = message.get_payload(decode=True).decode('utf-8', errors='ignore')
            elif content_type == 'text/html':
                msg_data['body_html'] = message.get_payload(decode=True).decode('utf-8', errors='ignore')
        
        return msg_data
    
    def _update_statistics(self, stats: Dict[str, Any], msg_data: Dict[str, Any]):
        """Update statistics with message data."""
        # Unique senders
        if msg_data['from']:
            stats['unique_senders'].add(msg_data['from'])
        
        # Unique recipients
        for field in ['to', 'cc', 'bcc']:
            if msg_data[field]:
                recipients = [r.strip() for r in msg_data[field].split(',')]
                stats['unique_recipients'].update(recipients)
        
        # Date range
        if msg_data['date']:
            try:
                msg_date = email.utils.parsedate_to_datetime(msg_data['date'])
                if stats['date_range']['earliest'] is None or msg_date < stats['date_range']['earliest']:
                    stats['date_range']['earliest'] = msg_date.isoformat()
                if stats['date_range']['latest'] is None or msg_date > stats['date_range']['latest']:
                    stats['date_range']['latest'] = msg_date.isoformat()
            except:
                pass
        
        # Subject keywords
        if msg_data['subject']:
            words = re.findall(r'\b\w+\b', msg_data['subject'].lower())
            stats['subject_keywords'].update(words)
        
        # Content type statistics
        if msg_data['body_html']:
            stats['html_emails'] += 1
        if msg_data['body_text']:
            stats['plain_text_emails'] += 1
        
        # Attachment count
        stats['attachment_count'] += len(msg_data['attachments'])
    
    def search_messages(self, mbox_path: str, search_terms: List[str], 
                       search_fields: List[str] = None) -> List[Dict[str, Any]]:
        """Search for specific terms in MBOX messages."""
        if search_fields is None:
            search_fields = ['subject', 'from', 'to', 'body_text', 'body_html']
        
        logger.info(f"Searching MBOX file: {mbox_path}")
        logger.info(f"Search terms: {search_terms}")
        logger.info(f"Search fields: {search_fields}")
        
        try:
            mbox = mailbox.mbox(mbox_path)
            results = []
            
            for i, message in enumerate(mbox):
                if i % 100 == 0:
                    logger.info(f"Searching message {i+1}/{len(mbox)}")
                
                msg_data = self._extract_message_data(message, i)
                
                # Search in specified fields
                for term in search_terms:
                    for field in search_fields:
                        if field in msg_data and msg_data[field]:
                            if term.lower() in str(msg_data[field]).lower():
                                result = {
                                    'message_index': i,
                                    'search_term': term,
                                    'matched_field': field,
                                    'message_data': msg_data
                                }
                                results.append(result)
                                break  # Found in this message, move to next term
            
            logger.info(f"Search complete: {len(results)} matches found")
            return results
            
        except Exception as e:
            logger.error(f"Error searching MBOX file {mbox_path}: {e}")
            return []
    
    def export_to_csv(self, analysis: Dict[str, Any], output_path: str) -> bool:
        """Export MBOX analysis to CSV file."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'message_index', 'message_id', 'from', 'to', 'cc', 'bcc',
                    'subject', 'date', 'content_type', 'has_attachments',
                    'attachment_count', 'body_length', 'size_bytes'
                ]
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for msg in analysis['messages']:
                    row = {
                        'message_index': msg['message_index'],
                        'message_id': msg['message_id'],
                        'from': msg['from'],
                        'to': msg['to'],
                        'cc': msg['cc'],
                        'bcc': msg['bcc'],
                        'subject': msg['subject'],
                        'date': msg['date'],
                        'content_type': msg['content_type'],
                        'has_attachments': msg['has_attachments'],
                        'attachment_count': len(msg['attachments']),
                        'body_length': len(msg['body_text']) + len(msg['body_html']),
                        'size_bytes': msg['size_bytes']
                    }
                    writer.writerow(row)
            
            logger.info(f"MBOX analysis exported to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def export_to_json(self, analysis: Dict[str, Any], output_path: str) -> bool:
        """Export MBOX analysis to JSON file."""
        try:
            with open(output_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(analysis, jsonfile, indent=2, ensure_ascii=False)
            
            logger.info(f"MBOX analysis exported to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return False
    
    def generate_html_report(self, analysis: Dict[str, Any], output_path: str) -> bool:
        """Generate HTML report for MBOX analysis."""
        try:
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>MBOX Analysis Report - {analysis['file_name']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background-color: #e8f4f8; padding: 15px; border-radius: 5px; }}
        .messages {{ margin-top: 20px; }}
        .message {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .message-header {{ font-weight: bold; color: #333; }}
        .message-body {{ margin-top: 10px; color: #666; }}
        .attachments {{ color: #0066cc; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MBOX Analysis Report</h1>
        <p><strong>File:</strong> {analysis['file_name']}</p>
        <p><strong>Size:</strong> {analysis['file_size']:,} bytes</p>
        <p><strong>Analysis Date:</strong> {analysis['analysis_timestamp']}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Total Messages</h3>
            <p style="font-size: 24px; margin: 0;">{analysis['total_messages']:,}</p>
        </div>
        <div class="stat-box">
            <h3>Unique Senders</h3>
            <p style="font-size: 24px; margin: 0;">{len(analysis['statistics']['unique_senders'])}</p>
        </div>
        <div class="stat-box">
            <h3>Unique Recipients</h3>
            <p style="font-size: 24px; margin: 0;">{len(analysis['statistics']['unique_recipients'])}</p>
        </div>
        <div class="stat-box">
            <h3>Attachments</h3>
            <p style="font-size: 24px; margin: 0;">{analysis['statistics']['attachment_count']}</p>
        </div>
    </div>
    
    <h2>Date Range</h2>
    <p><strong>Earliest:</strong> {analysis['statistics']['date_range']['earliest'] or 'Unknown'}</p>
    <p><strong>Latest:</strong> {analysis['statistics']['date_range']['latest'] or 'Unknown'}</p>
    
    <h2>Top Senders</h2>
    <table>
        <tr><th>Sender</th><th>Count</th></tr>
"""
            
            # Count sender frequency
            sender_counts = {}
            for msg in analysis['messages']:
                sender = msg['from']
                if sender:
                    sender_counts[sender] = sender_counts.get(sender, 0) + 1
            
            # Sort by count and add to HTML
            for sender, count in sorted(sender_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                html_content += f"        <tr><td>{sender}</td><td>{count}</td></tr>\n"
            
            html_content += """
    </table>
    
    <h2>Recent Messages</h2>
    <div class="messages">
"""
            
            # Add recent messages
            recent_messages = sorted(analysis['messages'], 
                                  key=lambda x: x['date'] or '', reverse=True)[:20]
            
            for msg in recent_messages:
                html_content += f"""
        <div class="message">
            <div class="message-header">
                From: {msg['from']} | To: {msg['to']} | Date: {msg['date']}
            </div>
            <div class="message-header">
                Subject: {msg['subject']}
            </div>
            <div class="message-body">
                {msg['body_text'][:200]}{'...' if len(msg['body_text']) > 200 else ''}
            </div>
"""
                if msg['attachments']:
                    html_content += f'            <div class="attachments">Attachments: {len(msg["attachments"])}</div>\n'
                
                html_content += "        </div>\n"
            
            html_content += """
    </div>
</body>
</html>
"""
            
            with open(output_path, 'w', encoding='utf-8') as htmlfile:
                htmlfile.write(html_content)
            
            logger.info(f"HTML report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return False

def main():
    """Command-line interface for MBOX viewer."""
    parser = argparse.ArgumentParser(
        description="MBOX Viewer for Project Revelare - Analyze and search MBOX email files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze an MBOX file
  python mbox_viewer.py analyze /path/to/emails.mbox
  
  # Search for specific terms
  python mbox_viewer.py search /path/to/emails.mbox -t "password" "confidential"
  
  # Export analysis to CSV
  python mbox_viewer.py analyze /path/to/emails.mbox -o analysis.csv
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze MBOX file')
    analyze_parser.add_argument('mbox_file', help='Path to MBOX file')
    analyze_parser.add_argument('-o', '--output', help='Output file (CSV, JSON, or HTML)')
    analyze_parser.add_argument('-f', '--format', choices=['csv', 'json', 'html'], 
                               default='html', help='Output format')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search MBOX file')
    search_parser.add_argument('mbox_file', help='Path to MBOX file')
    search_parser.add_argument('-t', '--terms', nargs='+', required=True, 
                              help='Search terms')
    search_parser.add_argument('-f', '--fields', nargs='+', 
                              choices=['subject', 'from', 'to', 'body_text', 'body_html'],
                              default=['subject', 'from', 'to', 'body_text'],
                              help='Fields to search in')
    search_parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    viewer = MboxViewer()
    
    if args.command == 'analyze':
        logger.info(f"Analyzing MBOX file: {args.mbox_file}")
        analysis = viewer.analyze_mbox_file(args.mbox_file)
        
        if not analysis:
            logger.error("Analysis failed")
            return 1
        
        if args.output:
            if args.format == 'csv':
                success = viewer.export_to_csv(analysis, args.output)
            elif args.format == 'json':
                success = viewer.export_to_json(analysis, args.output)
            else:  # html
                success = viewer.generate_html_report(analysis, args.output)
            
            if success:
                print(f"Analysis exported to: {args.output}")
            else:
                print("Export failed")
                return 1
        else:
            # Print summary
            print(f"MBOX Analysis Summary:")
            print(f"  File: {analysis['file_name']}")
            print(f"  Size: {analysis['file_size']:,} bytes")
            print(f"  Messages: {analysis['total_messages']:,}")
            print(f"  Unique Senders: {len(analysis['statistics']['unique_senders'])}")
            print(f"  Unique Recipients: {len(analysis['statistics']['unique_recipients'])}")
            print(f"  Attachments: {analysis['statistics']['attachment_count']}")
    
    elif args.command == 'search':
        logger.info(f"Searching MBOX file: {args.mbox_file}")
        results = viewer.search_messages(args.mbox_file, args.terms, args.fields)
        
        print(f"Search Results: {len(results)} matches found")
        
        if args.output:
            # Export search results
            with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['message_index', 'search_term', 'matched_field', 
                             'from', 'to', 'subject', 'date']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    msg = result['message_data']
                    writer.writerow({
                        'message_index': result['message_index'],
                        'search_term': result['search_term'],
                        'matched_field': result['matched_field'],
                        'from': msg['from'],
                        'to': msg['to'],
                        'subject': msg['subject'],
                        'date': msg['date']
                    })
            
            print(f"Search results exported to: {args.output}")
        else:
            # Print results
            for result in results[:10]:  # Show first 10 results
                msg = result['message_data']
                print(f"Match {result['message_index']}: '{result['search_term']}' in {result['matched_field']}")
                print(f"  From: {msg['from']}")
                print(f"  Subject: {msg['subject']}")
                print(f"  Date: {msg['date']}")
                print()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
