#!/usr/bin/env python3
"""
Unit tests for extractor.py module
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from revelare.core.extractor import process_file, run_extraction, group_urls_by_domain, filter_duplicate_emails
from revelare.utils.data_enhancer import EnhancedIndicator

class TestExtractor(unittest.TestCase):
    """Test cases for extractor module"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
    
    def test_classify_ip_private(self):
        """Test IP classification for private addresses"""
        self.assertEqual(classify_ip("10.0.0.1"), "Private")
        self.assertEqual(classify_ip("192.168.1.1"), "Private")
        self.assertEqual(classify_ip("172.16.0.1"), "Private")
        self.assertEqual(classify_ip("172.31.0.1"), "Private")
    
    def test_classify_ip_public(self):
        """Test IP classification for public addresses"""
        self.assertEqual(classify_ip("8.8.8.8"), "Public")
        self.assertEqual(classify_ip("1.1.1.1"), "Public")
        self.assertEqual(classify_ip("208.67.222.222"), "Public")
    
    def test_classify_ip_loopback(self):
        """Test IP classification for loopback addresses"""
        self.assertEqual(classify_ip("127.0.0.1"), "Loopback")
        self.assertEqual(classify_ip("127.1.1.1"), "Loopback")
    
    def test_classify_ip_multicast(self):
        """Test IP classification for multicast addresses"""
        self.assertEqual(classify_ip("224.0.0.1"), "Multicast")
        self.assertEqual(classify_ip("239.255.255.255"), "Multicast")
    
    def test_classify_ip_invalid(self):
        """Test IP classification for invalid addresses"""
        self.assertEqual(classify_ip("256.1.1.1"), "Invalid")
        self.assertEqual(classify_ip("1.1.1.256"), "Invalid")
        self.assertEqual(classify_ip("not.an.ip"), "Invalid")
        self.assertEqual(classify_ip("1.1.1"), "Invalid")
    
    def test_classify_ip_with_port(self):
        """Test IP classification with port numbers"""
        self.assertEqual(classify_ip("10.0.0.1:8080"), "Private")
        self.assertEqual(classify_ip("8.8.8.8:53"), "Public")
    
    def test_find_matches_in_text_basic(self):
        """Test basic regex matching in text"""
        text = "IP: 10.0.0.1, Email: test@example.com, URL: https://example.com"
        findings = find_matches_in_text(text, "test.txt")
        
        self.assertIn("IPv4", findings)
        self.assertIn("Email_Addresses", findings)
        self.assertIn("URLs", findings)
        
        self.assertIn("10.0.0.1", findings["IPv4"])
        self.assertIn("test@example.com", findings["Email_Addresses"])
        self.assertIn("https://example.com", findings["URLs"])
    
    def test_find_matches_in_text_empty(self):
        """Test regex matching with empty text"""
        findings = find_matches_in_text("", "empty.txt")
        self.assertEqual(findings, {})
        
        findings = find_matches_in_text(None, "none.txt")
        self.assertEqual(findings, {})
    
    def test_find_matches_in_text_no_matches(self):
        """Test regex matching with no matches"""
        text = "This is just plain text with no indicators"
        findings = find_matches_in_text(text, "plain.txt")
        self.assertEqual(findings, {})
    
    def test_process_file_text(self):
        """Test processing a text file"""
        # Create a temporary text file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("IP: 10.0.0.1\nEmail: test@example.com\nURL: https://example.com")
            temp_file = f.name
        
        try:
            findings = {}
            result = process_file(temp_file, findings)
            
            self.assertTrue(result)
            self.assertIn("IPv4", findings)
            self.assertIn("Email_Addresses", findings)
            self.assertIn("URLs", findings)
        finally:
            os.unlink(temp_file)
    
    def test_process_file_nonexistent(self):
        """Test processing a non-existent file"""
        findings = {}
        result = process_file("nonexistent.txt", findings)
        self.assertFalse(result)
    
    def test_process_file_unsupported_type(self):
        """Test processing an unsupported file type"""
        with tempfile.NamedTemporaryFile(suffix='.xyz', delete=False) as f:
            temp_file = f.name
        
        try:
            findings = {}
            result = process_file(temp_file, findings)
            self.assertFalse(result)
        finally:
            os.unlink(temp_file)
    
    def test_run_extraction_single_file(self):
        """Test running extraction on a single file"""
        # Create a temporary text file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("IP: 10.0.0.1\nEmail: test@example.com")
            temp_file = f.name
        
        try:
            findings = run_extraction([temp_file])
            
            self.assertIn("IPv4", findings)
            self.assertIn("Email_Addresses", findings)
            self.assertIn("Processing_Summary", findings)
            
            # Check processing summary
            summary = findings["Processing_Summary"]
            self.assertEqual(summary["Total_Files_Processed"], "1")
            self.assertEqual(summary["Total_Files_Failed"], "0")
            self.assertEqual(summary["Total_Files_Skipped"], "0")
        finally:
            os.unlink(temp_file)
    
    def test_run_extraction_multiple_files(self):
        """Test running extraction on multiple files"""
        # Create temporary text files
        temp_files = []
        try:
            for i in range(3):
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(f"IP: 10.0.0.{i+1}\nEmail: test{i}@example.com")
                    temp_files.append(f.name)
            
            findings = run_extraction(temp_files)
            
            self.assertIn("IPv4", findings)
            self.assertIn("Email_Addresses", findings)
            self.assertIn("Processing_Summary", findings)
            
            # Check processing summary
            summary = findings["Processing_Summary"]
            self.assertEqual(summary["Total_Files_Processed"], "3")
            self.assertEqual(summary["Total_Files_Failed"], "0")
            self.assertEqual(summary["Total_Files_Skipped"], "0")
        finally:
            for temp_file in temp_files:
                os.unlink(temp_file)
    
    def test_run_extraction_empty_list(self):
        """Test running extraction with empty file list"""
        findings = run_extraction([])
        self.assertEqual(findings, {})
    
    def test_run_extraction_invalid_input(self):
        """Test running extraction with invalid input"""
        findings = run_extraction(None)
        self.assertEqual(findings, {})
        
        findings = run_extraction("not a list")
        self.assertEqual(findings, {})

if __name__ == '__main__':
    unittest.main()
