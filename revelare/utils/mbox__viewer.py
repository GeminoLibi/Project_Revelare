import os
import re
import email
import mailbox
import json
import csv
import glob
from datetime import datetime
from typing import List, Dict, Any, Optional

from revelare.config.config import Config
from revelare.utils.logger import get_logger
from revelare.utils.security import SecurityValidator

logger = get_logger(__name__)

class EmailBrowser:
    def __init__(self):
        self.validator = SecurityValidator()
        self.supported_formats = {
            'mbox': ['.mbox', '.mbx'],
            'eml': ['.eml'],
            'pst': ['.pst']
        }

    def detect_email_format(self, path: str) -> Optional[str]:
        if not os.path.exists(path):
            return None

        if os.path.isdir(path):
            if os.path.exists(os.path.join(path, 'cur')):
                return 'maildir'
        else:
            _, ext = os.path.splitext(path.lower())
            for format_name, extensions in self.supported_formats.items():
                if ext in extensions:
                    return format_name
        return None

    def _format_file_size(self, size_bytes: int) -> str:
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024.0 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.2f} {size_names[i]}" if i > 0 else f"{int(size_bytes)} B"

    def get_email_archives_in_case(self, case_name: str) -> List[Dict[str, Any]]:
        try:
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            evidence_dir = os.path.join(case_path, 'evidence')
            if not os.path.exists(evidence_dir):
                return []

            email_archives = []
            for root, dirs, files in os.walk(evidence_dir):
                for item_name in files + dirs:
                    item_path = os.path.join(root, item_name)
                    email_format = self.detect_email_format(item_path)
                    if email_format:
                        size_bytes = os.path.getsize(item_path) if os.path.isfile(item_path) else 0
                        email_archives.append({
                            'path': item_path,
                            'format': email_format,
                            'size': size_bytes,
                            'formatted_size': self._format_file_size(size_bytes),
                            'relative_path': os.path.relpath(item_path, evidence_dir)
                        })
            return email_archives
        except Exception as e:
            logger.error(f"Error scanning case {case_name} for email archives: {e}")
            return []
    
    def analyze_email_archive(self, archive_path: str) -> Dict[str, Any]:
        email_format = self.detect_email_format(archive_path)
        if not email_format:
            logger.error(f"Unsupported email format: {archive_path}")
            return {}
        
        if email_format == 'mbox':
            return self._analyze_mbox_format(archive_path)
        elif email_format == 'eml':
            return self._analyze_eml_files(archive_path)
        else:
            logger.warning(f"Analysis for format '{email_format}' is not fully implemented.")
            return {
                'file_path': archive_path,
                'error': f"Analysis for {email_format.upper()} is not yet implemented."
            }

    def _analyze_mbox_format(self, mbox_path: str) -> Dict[str, Any]:
        if not self.validator.is_safe_path(mbox_path) or not os.path.exists(mbox_path):
            logger.error(f"MBOX file not found or path is unsafe: {mbox_path}")
            return {}
        
        try:
            mbox = mailbox.mbox(mbox_path)
            messages = [self._extract_message_data(msg, i) for i, msg in enumerate(mbox)]
            return {
                'file_path': mbox_path,
                'total_messages': len(messages),
                'messages': messages
            }
        except Exception as e:
            logger.error(f"Error analyzing MBOX file {mbox_path}: {e}")
            return {}

    def _analyze_eml_files(self, eml_path: str) -> Dict[str, Any]:
        eml_files = [eml_path] if os.path.isfile(eml_path) else glob.glob(os.path.join(eml_path, '**', '*.eml'), recursive=True)
        if not eml_files:
            return {}
            
        messages = []
        for i, eml_file in enumerate(eml_files):
            try:
                with open(eml_file, 'rb') as f:
                    msg = email.message_from_bytes(f.read())
                    messages.append(self._extract_message_data(msg, i))
            except Exception as e:
                logger.warning(f"Could not process EML file {eml_file}: {e}")
        
        return {
            'file_path': eml_path,
            'total_messages': len(messages),
            'messages': messages
        }

    def _extract_message_data(self, msg, index: int) -> Dict[str, Any]:
        
        def decode_header(header):
            if header is None:
                return ""
            decoded_parts = []
            for part, charset in email.header.decode_header(header):
                if isinstance(part, bytes):
                    decoded_parts.append(part.decode(charset or 'utf-8', 'ignore'))
                else:
                    decoded_parts.append(part)
            return "".join(decoded_parts)

        body_plain, body_html, attachments = "", "", []
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                if 'attachment' in content_disposition:
                    attachments.append({'filename': part.get_filename(), 'size': len(part.get_payload(decode=True) or b'')})
                elif content_type == 'text/plain' and not body_plain:
                    try:
                        body_plain = part.get_payload(decode=True).decode('utf-8', 'ignore')
                    except:
                        pass
                elif content_type == 'text/html' and not body_html:
                    try:
                        body_html = part.get_payload(decode=True).decode('utf-8', 'ignore')
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True).decode('utf-8', 'ignore')
                if msg.get_content_type() == 'text/html':
                    body_html = payload
                else:
                    body_plain = payload
            except:
                pass
        
        return {
            'message_index': index,
            'from': decode_header(msg.get('From')),
            'to': decode_header(msg.get('To')),
            'subject': decode_header(msg.get('Subject')),
            'date': msg.get('Date'),
            'body_plain': body_plain,
            'body_html': body_html,
            'attachments': attachments
        }