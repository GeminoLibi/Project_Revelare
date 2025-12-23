import os
import sys
import glob
import shutil
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.getcwd())

from revelare.cli.revelare_cli import process_project
from revelare.utils.logger import get_logger

# Configure logging
logger = get_logger("batch_processor")

CASES_DIR = r"E:\Cases"
OUTPUT_DIR = "cases"

class MockArgs:
    def __init__(self):
        self.debug = False
        self.verbose = True

def main():
    if not os.path.exists(CASES_DIR):
        print(f"Cases directory not found: {CASES_DIR}")
        return

    print(f"Scanning {CASES_DIR} for cases...")
    
    entries = os.listdir(CASES_DIR)
    processed_count = 0
    
    # Sort entries to process systematically
    entries.sort()

    for entry in entries:
        entry_path = os.path.join(CASES_DIR, entry)
        
        # Determine if this is a case (directory or archive)
        is_case = False
        project_name = ""
        input_files = []
        
        if os.path.isdir(entry_path):
            # It's a directory case
            project_name = entry
            is_case = True
            # Collect all files recursively
            for root, dirs, files in os.walk(entry_path):
                for f in files:
                    input_files.append(os.path.join(root, f))
        
        elif os.path.isfile(entry_path):
            # Check for archive extensions
            lower_name = entry.lower()
            if lower_name.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')) or lower_name.endswith('.7z.tmp'):
                project_name = os.path.splitext(entry)[0]
                if lower_name.endswith('.7z.tmp'):
                    project_name = entry.replace('.7z.tmp', '') # Remove .7z.tmp to get ID
                
                is_case = True
                input_files = [entry_path]

        if not is_case:
            continue
            
        if not input_files:
            print(f"Skipping empty case directory: {entry}")
            continue

        # Check if already processed
        report_path = os.path.join(OUTPUT_DIR, project_name, f"{project_name}_report.html")
        if os.path.exists(report_path):
            print(f"Skipping {project_name} (Report already exists)")
            continue

        print(f"\n[{processed_count+1}] Processing Case: {project_name}")
        print(f"Input: {entry_path}")
        print(f"File count: {len(input_files)}")
        
        try:
            # We use the existing process_project function
            # It handles extraction and reporting
            success = process_project(project_name, input_files, OUTPUT_DIR, MockArgs())
            
            if success:
                print(f"SUCCESS: {project_name}")
            else:
                print(f"FAILURE: {project_name}")
                
            processed_count += 1
            
        except Exception as e:
            print(f"ERROR processing {project_name}: {e}")
            import traceback
            traceback.print_exc()

    print(f"\nBatch processing complete. Processed {processed_count} cases.")
    
    # Generate Global Dashboard
    try:
        print("\nGenerating Global Investigation Dashboard...")
        from revelare.utils.global_reporter import GlobalReporter
        reporter = GlobalReporter(CASES_DIR)
        reporter.generate_dashboard(os.path.join(OUTPUT_DIR, "index.html"))
        print(f"Dashboard saved to: {os.path.join(OUTPUT_DIR, 'index.html')}")
    except Exception as e:
        print(f"Error generating dashboard: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

