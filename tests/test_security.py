#!/usr/bin/env python3
"""
Unit tests for security.py module
"""

import unittest
import tempfile
import os
import sys
from unittest.mock import MagicMock

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from revelare.utils.security import SecurityValidator, InputValidator

class TestSecurityValidator(unittest.TestCase):
    """Test cases for SecurityValidator class"""
    
    def test_is_safe_path_valid(self):
        """Test is_safe_path with valid paths"""
        self.assertTrue(SecurityValidator.is_safe_path("/safe/path/file.txt", "/safe/path"))
        self.assertTrue(SecurityValidator.is_safe_path("C:\\safe\\path", "C:\\safe\\path\\file.txt"))
    
    def test_is_safe_path_traversal(self):
        """Test is_safe_path with path traversal attempts"""
        self.assertFalse(SecurityValidator.is_safe_path("/safe/path/../../../etc/passwd", "/safe/path"))
        self.assertFalse(SecurityValidator.is_safe_path("C:\\safe\\path", "C:\\safe\\path\\..\\..\\windows\\system32"))
    
    def test_is_safe_path_empty(self):
        """Test is_safe_path with empty paths"""
        self.assertFalse(SecurityValidator.is_safe_path("file.txt", ""))
        self.assertFalse(SecurityValidator.is_safe_path("/safe/path", ""))
        self.assertFalse(SecurityValidator.is_safe_path(None, "file.txt"))
    
    def test_sanitize_filename_dangerous(self):
        """Test sanitize_filename with dangerous characters"""
        self.assertEqual(SecurityValidator.sanitize_filename("file<name>.txt"), "file_name_.txt")
    
    def test_validate_file_extension_valid(self):
        """Test validate_file_extension with valid extensions"""
        self.assertTrue(SecurityValidator.validate_file_extension("file.txt"))
        self.assertTrue(SecurityValidator.validate_file_extension("file.pdf"))
        self.assertTrue(SecurityValidator.validate_file_extension("file.docx"))
        self.assertTrue(SecurityValidator.validate_file_extension("file.zip"))
    
    def test_validate_file_extension_invalid(self):
        """Test validate_file_extension with invalid extensions"""
        self.assertFalse(SecurityValidator.validate_file_extension("file.exe"))
        self.assertFalse(SecurityValidator.validate_file_extension("file.bat"))
        self.assertFalse(SecurityValidator.validate_file_extension("file.cmd"))
        self.assertFalse(SecurityValidator.validate_file_extension("file.scr"))
    
    def test_validate_file_extension_no_extension(self):
        """Test validate_file_extension with no extension"""
        self.assertFalse(SecurityValidator.validate_file_extension("file"))
        self.assertFalse(SecurityValidator.validate_file_extension(""))
    
    def test_sanitize_filename_valid(self):
        """Test sanitize_filename with valid filenames"""
        self.assertEqual(SecurityValidator.sanitize_filename("file.txt"), "file.txt")
        self.assertEqual(SecurityValidator.sanitize_filename("my-file_123.txt"), "my-file_123.txt")
    
    def test_sanitize_filename_dangerous(self):
        """Test sanitize_filename with dangerous characters"""
        self.assertEqual(SecurityValidator.sanitize_filename("file<name>.txt"), "file_name_.txt")
        self.assertEqual(SecurityValidator.sanitize_filename("file>name.txt"), "file_name.txt")
        self.assertEqual(SecurityValidator.sanitize_filename("file\"name\".txt"), "file_name.txt")
        self.assertEqual(SecurityValidator.sanitize_filename("file|name.txt"), "file_name.txt")
        self.assertEqual(SecurityValidator.sanitize_filename("file?name.txt"), "file_name.txt")
        self.assertEqual(SecurityValidator.sanitize_filename("file*name.txt"), "file_name.txt")
    
    def test_sanitize_filename_empty(self):
        """Test sanitize_filename with empty input"""
        self.assertEqual(SecurityValidator.sanitize_filename(""), "unnamed_file")
        self.assertEqual(SecurityValidator.sanitize_filename(None), "unnamed_file")

class TestInputValidator(unittest.TestCase):
    """Test cases for InputValidator class"""
    
    def test_is_valid_ip_valid(self):
        """Test is_valid_ip with valid IP addresses"""
        self.assertTrue(InputValidator.is_valid_ip("192.168.1.1"))
        self.assertTrue(InputValidator.is_valid_ip("10.0.0.1"))
        self.assertTrue(InputValidator.is_valid_ip("8.8.8.8"))
        self.assertTrue(InputValidator.is_valid_ip("127.0.0.1"))
    
    def test_is_valid_ip_invalid(self):
        """Test is_valid_ip with invalid IP addresses"""
        self.assertFalse(InputValidator.is_valid_ip("256.1.1.1"))
        self.assertFalse(InputValidator.is_valid_ip("1.1.1.256"))
        self.assertFalse(InputValidator.is_valid_ip("not.an.ip"))
        self.assertFalse(InputValidator.is_valid_ip("1.1.1"))
        self.assertFalse(InputValidator.is_valid_ip(""))
        self.assertFalse(InputValidator.is_valid_ip(None))
    
    def test_validate_indicator_search_valid(self):
        """Test validate_indicator_search with valid search terms"""
        valid, msg = InputValidator.validate_indicator_search("test")
        self.assertTrue(valid)
        self.assertEqual(msg, "File processed successfully")
        
        valid, msg = InputValidator.validate_indicator_search("192.168.1.1")
        self.assertTrue(valid)
        self.assertEqual(msg, "File processed successfully")
        
        valid, msg = InputValidator.validate_indicator_search("test@example.com")
        self.assertTrue(valid)
        self.assertEqual(msg, "File processed successfully")
    
    def test_validate_indicator_search_invalid(self):
        """Test validate_indicator_search with invalid search terms"""
        valid, msg = InputValidator.validate_indicator_search("")
        self.assertFalse(valid)
        self.assertEqual(msg, "Search term cannot be empty")
        
        valid, msg = InputValidator.validate_indicator_search("a" * 1001)
        self.assertFalse(valid)
        self.assertEqual(msg, "Search term too long")
        
        valid, msg = InputValidator.validate_indicator_search("SELECT * FROM users")
        self.assertFalse(valid)
        self.assertEqual(msg, "Search term contains potentially dangerous patterns")
    
    def test_sanitize_html_input_safe(self):
        """Test sanitize_html_input with safe input"""
        self.assertEqual(InputValidator.sanitize_html_input("Hello World"), "Hello World")
        self.assertEqual(InputValidator.sanitize_html_input("123"), "123")
        self.assertEqual(InputValidator.sanitize_html_input("test@example.com"), "test@example.com")
    
    def test_sanitize_html_input_script_tags(self):
        """Test sanitize_html_input with script tags"""
        input_text = "<script>alert('xss')</script>Hello"
        result = InputValidator.sanitize_html_input(input_text)
        self.assertNotIn("<script>", result)
        self.assertNotIn("</script>", result)
        self.assertIn("Hello", result)
    
    def test_sanitize_html_input_javascript_urls(self):
        """Test sanitize_html_input with javascript URLs"""
        input_text = "javascript:alert('xss')"
        result = InputValidator.sanitize_html_input(input_text)
        self.assertNotIn("javascript:", result)
    
    def test_sanitize_html_input_data_urls(self):
        """Test sanitize_html_input with data URLs"""
        input_text = "data:text/html,<script>alert('xss')</script>"
        result = InputValidator.sanitize_html_input(input_text)
        self.assertNotIn("data:", result)
    
    def test_sanitize_html_input_empty(self):
        """Test sanitize_html_input with empty input"""
        self.assertEqual(InputValidator.sanitize_html_input(""), "")
        self.assertEqual(InputValidator.sanitize_html_input(None), "")
        self.assertEqual(InputValidator.sanitize_html_input(123), "123")
    

if __name__ == '__main__':
    unittest.main()
