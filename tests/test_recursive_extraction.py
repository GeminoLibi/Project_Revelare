#!/usr/bin/env python3
"""
Test script to verify recursive extraction is working properly
"""

import os
import sys
import zipfile
import tempfile
import shutil

def create_test_archive():
    """Create a test archive with nested structure."""
    print("Creating test archive with nested structure...")
    
    # Create temporary directory for test files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create nested structure
        nested_dir = os.path.join(temp_dir, "nested_data")
        os.makedirs(nested_dir, exist_ok=True)
        
        # Create some test files
        test_files = {
            "level1_file.txt": "This is a level 1 file",
            "nested_data/level2_file.txt": "This is a level 2 file",
            "nested_data/level2_data.json": '{"level": 2, "data": "nested"}'
        }
        
        for file_path, content in test_files.items():
            full_path = os.path.join(temp_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, 'w') as f:
                f.write(content)
        
        # Create nested archive
        nested_archive = os.path.join(temp_dir, "nested_archive.zip")
        with zipfile.ZipFile(nested_archive, 'w') as zf:
            zf.write(os.path.join(temp_dir, "level1_file.txt"), "level1_file.txt")
            zf.write(os.path.join(temp_dir, "nested_data/level2_file.txt"), "nested_data/level2_file.txt")
            zf.write(os.path.join(temp_dir, "nested_data/level2_data.json"), "nested_data/level2_data.json")
        
        # Create main archive containing the nested archive
        main_archive = "test_nested_archive.zip"
        with zipfile.ZipFile(main_archive, 'w') as zf:
            zf.write(nested_archive, "nested_archive.zip")
            zf.write(os.path.join(temp_dir, "level1_file.txt"), "level1_file.txt")
        
        print(f"✓ Created test archive: {main_archive}")
        return main_archive

def test_recursive_extraction():
    """Test the recursive extraction functionality."""
    print("Testing recursive extraction...")
    
    # Create test archive
    test_archive = create_test_archive()
    
    try:
        # Import the string_search module
        from string_search import recursive_extract_archives
        import logging
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger("test_extraction")
        
        # Create extraction directory
        extract_dir = "test_extraction_output"
        os.makedirs(extract_dir, exist_ok=True)
        
        print(f"Extracting {test_archive} to {extract_dir}...")
        
        # Extract recursively
        extracted_dirs = recursive_extract_archives(test_archive, extract_dir, logger)
        
        print(f"✓ Extraction completed. Extracted directories: {len(extracted_dirs)}")
        
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
        for root, dirs, files in os.walk(extract_dir):
            if "nested_archive" in root and any(f.endswith('.json') for f in files):
                nested_found = True
                break
        
        if nested_found:
            print("✓ Nested archive was properly extracted!")
        else:
            print("❌ Nested archive was NOT extracted properly")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during extraction: {e}")
        return False
    
    finally:
        # Cleanup
        if os.path.exists(test_archive):
            os.remove(test_archive)
        if os.path.exists("test_extraction_output"):
            shutil.rmtree("test_extraction_output")

def main():
    """Main test function."""
    print("Project Revelare - Recursive Extraction Test")
    print("=" * 50)
    
    success = test_recursive_extraction()
    
    if success:
        print("\n✅ Recursive extraction test PASSED!")
    else:
        print("\n❌ Recursive extraction test FAILED!")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
