#!/usr/bin/env python3
"""
Unit tests for data_enhancer.py module
"""

import unittest
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from revelare.utils.data_enhancer import DataEnhancer, EnhancedIndicator

class TestEnhancedIndicator(unittest.TestCase):
    """Test cases for EnhancedIndicator dataclass"""
    
    def test_enhanced_indicator_creation(self):
        """Test creating an EnhancedIndicator instance"""
        indicator = EnhancedIndicator(
            value="192.168.1.1",
            category="IPv4",
            context="Test context",
            file_name="test.txt",
            line_number=1,
            position=100
        )
        
        self.assertEqual(indicator.value, "192.168.1.1")
        self.assertEqual(indicator.category, "IPv4")
        self.assertEqual(indicator.context, "Test context")
        self.assertEqual(indicator.file_name, "test.txt")
        self.assertEqual(indicator.line_number, 1)
        self.assertEqual(indicator.position, 100)
        self.assertEqual(indicator.confidence_score, 1.0)
        self.assertTrue(indicator.is_relevant)
    
    def test_enhanced_indicator_defaults(self):
        """Test EnhancedIndicator with default values"""
        indicator = EnhancedIndicator(
            value="test@example.com",
            category="Email_Addresses",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        
        self.assertEqual(indicator.position, 0)
        self.assertIsNone(indicator.timestamp)
        self.assertIsNone(indicator.source_port)
        self.assertIsNone(indicator.destination_port)
        self.assertIsNone(indicator.protocol)
        self.assertIsNone(indicator.user_agent)
        self.assertIsNone(indicator.host_header)
        self.assertIsNone(indicator.session_id)
        self.assertEqual(indicator.confidence_score, 1.0)
        self.assertTrue(indicator.is_relevant)
        self.assertIsNotNone(indicator.metadata)

class TestDataEnhancer(unittest.TestCase):
    """Test cases for DataEnhancer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.enhancer = DataEnhancer()
    
    def test_create_enhanced_indicator(self):
        """Test create_enhanced_indicator method"""
        enhanced = self.enhancer.create_enhanced_indicator(
            indicator="192.168.1.1",
            category="IPv4",
            context="Test context",
            file_name="test.txt",
            position=100
        )
        
        self.assertIsInstance(enhanced, EnhancedIndicator)
        self.assertEqual(enhanced.value, "192.168.1.1")
        self.assertEqual(enhanced.category, "IPv4")
        self.assertEqual(enhanced.context, "Test context")
        self.assertEqual(enhanced.file_name, "test.txt")
        self.assertEqual(enhanced.position, 100)
    
    def test_is_irrelevant_relevant_indicator(self):
        """Test is_irrelevant with relevant indicators"""
        # Test with IP address
        ip_indicator = EnhancedIndicator(
            value="192.168.1.1",
            category="IPv4",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertFalse(self.enhancer.is_irrelevant(ip_indicator))
        
        # Test with email address (should be irrelevant because it's example.com)
        email_indicator = EnhancedIndicator(
            value="test@example.com",
            category="Email_Addresses",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertTrue(self.enhancer.is_irrelevant(email_indicator))
        
        # Test with URL (should be irrelevant because it's example.com)
        url_indicator = EnhancedIndicator(
            value="https://example.com",
            category="URLs",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertTrue(self.enhancer.is_irrelevant(url_indicator))
    
    def test_is_irrelevant_irrelevant_indicator(self):
        """Test is_irrelevant with irrelevant indicators"""
        # Test with localhost IP
        localhost_indicator = EnhancedIndicator(
            value="127.0.0.1",
            category="IPv4",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertTrue(self.enhancer.is_irrelevant(localhost_indicator))
        
        # Test with example.com email (should be irrelevant)
        example_email_indicator = EnhancedIndicator(
            value="test@example.com",
            category="Email_Addresses",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertTrue(self.enhancer.is_irrelevant(example_email_indicator))
        
        # Test with example.com URL
        example_url_indicator = EnhancedIndicator(
            value="https://example.com",
            category="URLs",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertTrue(self.enhancer.is_irrelevant(example_url_indicator))
    
    def test_is_irrelevant_edge_cases(self):
        """Test is_irrelevant with edge cases"""
        # Test with None indicator
        self.assertTrue(self.enhancer.is_irrelevant(None))
        
        # Test with empty value
        empty_indicator = EnhancedIndicator(
            value="",
            category="IPv4",
            context="Test context",
            file_name="test.txt",
            line_number=1
        )
        self.assertTrue(self.enhancer.is_irrelevant(empty_indicator))
    
    def test_compile_filters(self):
        """Test _compile_filters method"""
        compiled_filters = self.enhancer._compile_filters()
        self.assertIsInstance(compiled_filters, dict)
        
        # Check that filters are compiled regex patterns
        for category, patterns in compiled_filters.items():
            self.assertIsInstance(patterns, list)
            for pattern in patterns:
                self.assertTrue(hasattr(pattern, 'search'))
    
    def test_compile_patterns(self):
        """Test _compile_patterns method"""
        compiled_patterns = self.enhancer._compile_patterns()
        self.assertIsInstance(compiled_patterns, dict)
        
        # Check that patterns are compiled regex patterns
        for category, pattern in compiled_patterns.items():
            self.assertTrue(hasattr(pattern, 'search'))
    
    def test_is_relevant_indicator_ip(self):
        """Test _is_relevant_indicator with IP addresses"""
        # Valid IP
        ip_indicator = EnhancedIndicator("192.168.1.1", "IPv4", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(ip_indicator))
        
        ip_indicator = EnhancedIndicator("10.0.0.1", "IPv4", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(ip_indicator))
        
        ip_indicator = EnhancedIndicator("8.8.8.8", "IPv4", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(ip_indicator))
        
        # Invalid IPs
        ip_indicator = EnhancedIndicator("127.0.0.1", "IPv4", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(ip_indicator))
        
        ip_indicator = EnhancedIndicator("0.0.0.0", "IPv4", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(ip_indicator))
    
    def test_is_relevant_indicator_email(self):
        """Test _is_relevant_indicator with email addresses"""
        # Valid emails
        email_indicator = EnhancedIndicator("user@company.com", "Email_Addresses", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(email_indicator))

        # Invalid emails (filtered out)
        email_indicator = EnhancedIndicator("admin@organization.org", "Email_Addresses", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(email_indicator))  # admin@ pattern

        email_indicator = EnhancedIndicator("test@example.com", "Email_Addresses", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(email_indicator))  # test@ pattern

        email_indicator = EnhancedIndicator("user@test.com", "Email_Addresses", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(email_indicator))  # test@ pattern
    
    def test_is_relevant_indicator_url(self):
        """Test _is_relevant_indicator with URLs"""
        # Valid URLs
        url_indicator = EnhancedIndicator("https://malicious-site.com", "URLs", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(url_indicator))
        
        url_indicator = EnhancedIndicator("http://suspicious-domain.net", "URLs", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(url_indicator))
        
        # Invalid URLs
        url_indicator = EnhancedIndicator("https://example.com", "URLs", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(url_indicator))
        
        url_indicator = EnhancedIndicator("http://test.com", "URLs", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(url_indicator))
    
    def test_is_relevant_indicator_other(self):
        """Test _is_relevant_indicator with other indicators"""
        # Valid indicators
        file_indicator = EnhancedIndicator("malware.exe", "File_Names", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(file_indicator))
        
        file_indicator = EnhancedIndicator("suspicious_file.pdf", "File_Names", "Test", "test.txt", 1)
        self.assertTrue(self.enhancer._is_relevant_indicator(file_indicator))
        
        # Invalid indicators
        file_indicator = EnhancedIndicator("ab", "File_Names", "Test", "test.txt", 1)  # Too short
        self.assertFalse(self.enhancer._is_relevant_indicator(file_indicator))
        
        file_indicator = EnhancedIndicator("test_document.pdf", "File_Names", "Test", "test.txt", 1)
        self.assertFalse(self.enhancer._is_relevant_indicator(file_indicator))

if __name__ == '__main__':
    unittest.main()
