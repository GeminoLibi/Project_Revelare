#!/usr/bin/env python3
"""
Integration tests for Project Revelare
"""

import unittest
import tempfile
import os
import sys
import subprocess
import json
import time
from unittest.mock import patch, MagicMock

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from revelare.core.extractor import run_extraction
from revelare.utils.reporter import ReportGenerator
from revelare.utils.reporter import ReportGenerator as Reporter
from revelare.cli.suite import app

class TestCLIIntegration(unittest.TestCase):
    """Integration tests for CLI functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        self.output_dir = tempfile.mkdtemp(prefix='revelare_test_')
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
    
    def test_cli_basic_functionality(self):
        """Test basic CLI functionality with sample data"""
        # Create a test file
        test_file = os.path.join(self.output_dir, 'test_evidence.txt')
        with open(test_file, 'w') as f:
            f.write("""
Network Activity Log:
2024-01-15 14:30:25 - Connection from 10.0.0.5:8080 to 192.168.1.100:443
2024-01-15 14:30:26 - HTTP Request: GET /api/data HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

Email Communications:
From: john.doe@example.com
To: jane.smith@company.com
Subject: Project Update
Date: Mon, 15 Jan 2024 14:30:00 GMT

Suspicious URLs:
https://malicious-site.com/phishing
http://suspicious-domain.net/data

Session Information:
Session-ID: abc123def456
Cookie: session_token=xyz789
""")
        
        # Test the extraction process
        findings = run_extraction([test_file])
        
        # Verify findings
        self.assertIn("IPv4", findings)
        self.assertIn("Email_Addresses", findings)
        self.assertIn("URLs", findings)
        self.assertIn("Processing_Summary", findings)
        
        # Check specific indicators
        self.assertIn("10.0.0.5", findings["IPv4"])
        self.assertIn("192.168.1.100", findings["IPv4"])
        self.assertIn("john.doe@example.com", findings["Email_Addresses"])
        self.assertIn("jane.smith@company.com", findings["Email_Addresses"])
        self.assertIn("https://malicious-site.com/phishing", findings["URLs"])
        self.assertIn("http://suspicious-domain.net/data", findings["URLs"])
        
        # Check processing summary
        summary = findings["Processing_Summary"]
        self.assertEqual(summary["Total_Files_Processed"], "1")
        self.assertEqual(summary["Total_Files_Failed"], "0")
        self.assertEqual(summary["Total_Files_Skipped"], "0")
    
    def test_cli_multiple_files(self):
        """Test CLI with multiple files"""
        # Create multiple test files
        test_files = []
        for i in range(3):
            test_file = os.path.join(self.output_dir, f'test_evidence_{i}.txt')
            with open(test_file, 'w') as f:
                f.write(f"""
File {i} Network Activity:
2024-01-15 14:30:2{i} - Connection from 10.0.0.{i+1}:808{i} to 192.168.1.{i+10}:443
Email: user{i}@example.com
URL: https://site{i}.com/page{i}
""")
            test_files.append(test_file)
        
        # Test the extraction process
        findings = run_extraction(test_files)
        
        # Verify findings
        self.assertIn("IPv4", findings)
        self.assertIn("Email_Addresses", findings)
        self.assertIn("URLs", findings)
        self.assertIn("Processing_Summary", findings)
        
        # Check processing summary
        summary = findings["Processing_Summary"]
        self.assertEqual(summary["Total_Files_Processed"], "3")
        self.assertEqual(summary["Total_Files_Failed"], "0")
        self.assertEqual(summary["Total_Files_Skipped"], "0")
        
        # Check that we found indicators from all files
        self.assertGreaterEqual(len(findings["IPv4"]), 3)
        self.assertGreaterEqual(len(findings["Email_Addresses"]), 3)
        self.assertGreaterEqual(len(findings["URLs"]), 3)
    
    def test_cli_json_csv_files(self):
        """Test CLI with JSON and CSV files"""
        # Create JSON test file
        json_file = os.path.join(self.output_dir, 'test_data.json')
        with open(json_file, 'w') as f:
            json.dump({
                "network_events": [
                    {
                        "timestamp": "2024-01-15T14:30:25Z",
                        "source_ip": "10.0.0.5",
                        "source_port": 8080,
                        "destination_ip": "192.168.1.100",
                        "destination_port": 443,
                        "protocol": "tcp"
                    }
                ],
                "emails": [
                    {
                        "from": "john.doe@example.com",
                        "to": "jane.smith@company.com",
                        "subject": "Project Update"
                    }
                ]
            }, f)
        
        # Create CSV test file
        csv_file = os.path.join(self.output_dir, 'test_data.csv')
        with open(csv_file, 'w') as f:
            f.write("timestamp,source_ip,source_port,destination_ip,destination_port,protocol,email,url\n")
            f.write("2024-01-15 14:30:25,10.0.0.5,8080,192.168.1.100,443,tcp,john.doe@example.com,https://malicious-site.com/phishing\n")
        
        # Test the extraction process
        findings = run_extraction([json_file, csv_file])
        
        # Verify findings
        self.assertIn("IPv4", findings)
        self.assertIn("Email_Addresses", findings)
        self.assertIn("URLs", findings)
        self.assertIn("Processing_Summary", findings)
        
        # Check processing summary
        summary = findings["Processing_Summary"]
        self.assertEqual(summary["Total_Files_Processed"], "2")
        self.assertEqual(summary["Total_Files_Failed"], "0")
        self.assertEqual(summary["Total_Files_Skipped"], "0")

class TestWebInterfaceIntegration(unittest.TestCase):
    """Integration tests for web interface functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.output_dir = tempfile.mkdtemp(prefix='revelare_web_test_')
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
    
    def test_web_interface_home_page(self):
        """Test web interface home page"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Project Revelare', response.data)
        self.assertIn(b'File Analysis', response.data)
    
    def test_web_interface_link_analysis_page(self):
        """Test web interface link analysis page"""
        response = self.client.get('/link_analysis')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Link Analysis Engine', response.data)
        self.assertIn(b'Search for connections', response.data)
    
    def test_web_interface_project_creation(self):
        """Test web interface project creation"""
        # Create a test file
        test_file = os.path.join(self.output_dir, 'test_evidence.txt')
        with open(test_file, 'w') as f:
            f.write("""
Network Activity:
2024-01-15 14:30:25 - Connection from 10.0.0.5:8080 to 192.168.1.100:443
Email: test@example.com
URL: https://malicious-site.com/phishing
""")
        
        # Test project creation
        with open(test_file, 'rb') as f:
            response = self.client.post('/', data={
                'project_name': 'test_project',
                'files': f
            })
        
        # Should redirect after successful creation
        self.assertEqual(response.status_code, 302)
    
    def test_web_interface_project_listing(self):
        """Test web interface project listing"""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Existing Projects', response.data)
    
    def test_web_interface_search_functionality(self):
        """Test web interface search functionality"""
        # Test search with no results
        response = self.client.post('/link_analysis', data={
            'search_term': 'nonexistent@example.com'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'No connections found', response.data)
    
    def test_web_interface_export_functionality(self):
        """Test web interface export functionality"""
        # Test JSON export (should return 404 for non-existent project)
        response = self.client.get('/export/nonexistent/json')
        self.assertEqual(response.status_code, 404)
        
        # Test CSV export (should return 404 for non-existent project)
        response = self.client.get('/export/nonexistent/csv')
        self.assertEqual(response.status_code, 404)
        
        # Test legal warrant export (should return 404 for non-existent project)
        response = self.client.get('/export/nonexistent/warrant')
        self.assertEqual(response.status_code, 404)

class TestReportGenerationIntegration(unittest.TestCase):
    """Integration tests for report generation"""
    
    def test_report_generation_basic(self):
        """Test basic report generation"""
        # Create sample findings
        findings = {
            "IPv4": {
                "192.168.1.1": "File: test.txt | Position: 0 | Type: Private",
                "10.0.0.1": "File: test.txt | Position: 0 | Type: Private"
            },
            "Email_Addresses": {
                "test@example.com": "File: test.txt | Position: 0"
            },
            "URLs": {
                "https://malicious-site.com": "File: test.txt | Position: 0"
            },
            "Processing_Summary": {
                "Total_Files_Processed": "1",
                "Total_Files_Failed": "0",
                "Total_Files_Skipped": "0",
                "Processing_Time_Seconds": "0.1"
            }
        }
        
        # Generate report
        report_html = ReportGenerator().generate_report("test_project", findings)
        
        # Verify report content
        self.assertIn("Intelligence Report: test_project", report_html)
        self.assertIn("192.168.1.1", report_html)
        self.assertIn("test@example.com", report_html)
        self.assertIn("https://malicious-site.com", report_html)
        self.assertIn("Processing Summary", report_html)
    
    def test_report_generation_empty_findings(self):
        """Test report generation with empty findings"""
        findings = {
            "Processing_Summary": {
                "Total_Files_Processed": "0",
                "Total_Files_Failed": "0",
                "Total_Files_Skipped": "1",
                "Processing_Time_Seconds": "0.0"
            }
        }
        
        # Generate report
        report_html = ReportGenerator().generate_report("empty_project", findings)
        
        # Verify report content
        self.assertIn("Intelligence Report: empty_project", report_html)
        self.assertIn("No indicators found", report_html)
        self.assertIn("Processing Summary", report_html)
    
    def test_report_generation_large_dataset(self):
        """Test report generation with large dataset"""
        # Create large findings dataset
        findings = {
            "IPv4": {},
            "Email_Addresses": {},
            "URLs": {},
            "Processing_Summary": {
                "Total_Files_Processed": "100",
                "Total_Files_Failed": "0",
                "Total_Files_Skipped": "0",
                "Processing_Time_Seconds": "5.0"
            }
        }
        
        # Add many IP addresses
        for i in range(100):
            findings["IPv4"][f"192.168.1.{i}"] = f"File: test{i}.txt | Position: 0 | Type: Private"
        
        # Add many email addresses
        for i in range(50):
            findings["Email_Addresses"][f"user{i}@example.com"] = f"File: test{i}.txt | Position: 0"
        
        # Add many URLs
        for i in range(25):
            findings["URLs"][f"https://site{i}.com/page{i}"] = f"File: test{i}.txt | Position: 0"
        
        # Generate report
        report_html = ReportGenerator().generate_report("large_project", findings)
        
        # Verify report content
        self.assertIn("Intelligence Report: large_project", report_html)
        self.assertIn("192.168.1.0", report_html)  # First IP
        self.assertIn("user0@example.com", report_html)  # First email
        self.assertIn("https://site0.com/page0", report_html)  # First URL
        self.assertIn("Processing Summary", report_html)

if __name__ == '__main__':
    unittest.main()
