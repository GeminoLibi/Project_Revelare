#!/usr/bin/env python3
"""
Test script to verify case management extraction is working properly
"""

import os
import sys
import zipfile
import tempfile
import shutil

def create_test_case_archive():
    """Create a test archive for case management testing."""
    print("Creating test case archive...")
    
    # Create temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create nested structure
        nested_dir = os.path.join(temp_dir, "email_data")
        os.makedirs(nested_dir, exist_ok=True)
        
        # Create some test email files
        emails = [
            {
                'id': 'email_001',
                'from': 'test@example.com',
                'subject': 'Test Email 1',
                'body': 'This is a test email for case management'
            },
            {
                'id': 'email_002', 
                'from': 'test2@example.com',
                'subject': 'Test Email 2',
                'body': 'Another test email with important data'
            }
        ]
        
        for email in emails:
            file_path = os.path.join(nested_dir, f"{email['id']}.json")
            with open(file_path, 'w') as f:
                import json
                json.dump(email, f, indent=2)
        
        # Create nested archive
        nested_archive = os.path.join(temp_dir, "nested_emails.zip")
        with zipfile.ZipFile(nested_archive, 'w') as zf:
            for email in emails:
                file_path = os.path.join(nested_dir, f"{email['id']}.json")
                zf.write(file_path, f"email_data/{email['id']}.json")
        
        # Create main archive containing the nested archive
        main_archive = "test_case_archive.zip"
        with zipfile.ZipFile(main_archive, 'w') as zf:
            zf.write(nested_archive, "nested_emails.zip")
            # Add a top-level file too
            zf.writestr("case_info.txt", "This is case information")
        
        print(f"✓ Created test case archive: {main_archive}")
        return main_archive

def test_case_extraction():
    """Test the case extraction functionality."""
    print("Testing case extraction...")
    
    # Create test archive
    test_archive = create_test_case_archive()
    
    try:
        # Import the string_search module
        from string_search import search_strings_in_archive
        import logging
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger("test_case_extraction")
        
        # Create extraction directory
        extract_dir = "test_case_output"
        os.makedirs(extract_dir, exist_ok=True)
        
        print(f"Extracting {test_archive} to {extract_dir}...")
        
        # Extract using search_strings_in_archive with empty search strings
        search_strings_in_archive(
            test_archive,
            [],  # Empty search strings - just extract
            0,   # No context needed
            logger,
            extract_to_dir=extract_dir
        )
        
        print(f"✓ Extraction completed")
        
        # Check what was extracted
        print("\nExtracted structure:")
        for root, dirs, files in os.walk(extract_dir):
            level = root.replace(extract_dir, '').count(os.sep)
            indent = ' ' * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                print(f"{subindent}{file}")
        
        # Check if nested archive was extracted
        nested_found = False
        json_files_found = 0
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith('.json'):
                    json_files_found += 1
                    nested_found = True
        
        if nested_found and json_files_found >= 2:
            print(f"✓ Nested archive was properly extracted! Found {json_files_found} JSON files")
        else:
            print("❌ Nested archive was NOT extracted properly")
        
        return nested_found
        
    except Exception as e:
        print(f"❌ Error during extraction: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Cleanup
        if os.path.exists(test_archive):
            os.remove(test_archive)
        if os.path.exists("test_case_output"):
            shutil.rmtree("test_case_output")

def main():
    """Main test function."""
    print("Project Revelare - Case Extraction Test")
    print("=" * 45)
    
    success = test_case_extraction()
    
    if success:
        print("\n✅ Case extraction test PASSED!")
    else:
        print("\n❌ Case extraction test FAILED!")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
