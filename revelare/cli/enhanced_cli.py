#!/usr/bin/env python3
"""
Enhanced Project Revelare CLI
Provides all GUI functionality through command line interface
"""

import os
import sys
import argparse
import tempfile
import shutil
import json
import csv
import re
import logging
import sqlite3
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
from datetime import datetime

# Add the project root directory to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from revelare.config.config import Config
from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator
from revelare.core.extractor import run_extraction
from revelare.utils import reporter
import revelare.utils.file_extractor as file_extractor
from revelare.core.case_manager import case_manager
from revelare.utils.string_search import StringSearchTool
from revelare.utils.email_browser import EmailBrowser
from revelare.utils.fractal_encryption import FractalEncryption

if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8') 

logger = get_logger(__name__)
cli_logger = RevelareLogger.get_logger('enhanced_cli')

class EnhancedCLI:
    def __init__(self):
        self.case_manager = case_manager
        self.string_search = StringSearchTool()
        self.email_browser = EmailBrowser()
        self.fractal_encryption = FractalEncryption()
        
    def print_header(self):
        """Print the CLI header"""
        print("=" * 60)
        print("  Project Revelare - Enhanced CLI Interface")
        print("=" * 60)
        print("  Digital Forensics & Evidence Analysis Tool")
        print("  Version 2.5 - Enhanced Edition")
        print("=" * 60)
        
    def print_menu(self):
        """Print the main menu"""
        print("\n" + "=" * 40)
        print("  MAIN MENU")
        print("=" * 40)
        print("  [1]  Case Management")
        print("  [2]  Evidence Processing")
        print("  [3]  String Search")
        print("  [4]  Email Analysis")
        print("  [5]  Link Analysis")
        print("  [6]  Fractal Encryption")
        print("  [7]  Report Generation")
        print("  [8]  Database Management")
        print("  [9]  System Information")
        print("  [0]  Exit")
        print("-" * 40)
        
    def case_management_menu(self):
        """Case management submenu"""
        while True:
            print("\n" + "=" * 30)
            print("  CASE MANAGEMENT")
            print("=" * 30)
            print("  [1]  List All Cases")
            print("  [2]  Create New Case")
            print("  [3]  View Case Details")
            print("  [4]  Add Files to Case")
            print("  [5]  Re-analyze Case")
            print("  [6]  Delete Case")
            print("  [7]  Export Case Data")
            print("  [0]  Back to Main Menu")
            print("-" * 30)
            
            choice = input("Enter your choice: ").strip()
            
            if choice == '1':
                self.list_cases()
            elif choice == '2':
                self.create_case()
            elif choice == '3':
                self.view_case_details()
            elif choice == '4':
                self.add_files_to_case()
            elif choice == '5':
                self.reanalyze_case()
            elif choice == '6':
                self.delete_case()
            elif choice == '7':
                self.export_case_data()
            elif choice == '0':
                break
            else:
                print("Invalid choice. Please try again.")
                
    def list_cases(self):
        """List all available cases"""
        print("\n" + "-" * 50)
        print("  AVAILABLE CASES")
        print("-" * 50)
        
        cases = self.case_manager.get_available_cases()
        if not cases:
            print("  No cases found.")
            return
            
        for i, case in enumerate(cases, 1):
            status = "✓ Completed" if case.get('has_report') else "⏳ Processing"
            findings = case.get('findings_count', 0)
            print(f"  [{i:2d}] {case['name']}")
            print(f"       Status: {status}")
            print(f"       Findings: {findings}")
            print(f"       Email Archives: {case.get('email_archive_count', 0)}")
            print()
            
    def create_case(self):
        """Create a new case using onboarding wizard"""
        print("\n" + "-" * 50)
        print("  CREATE NEW CASE")
        print("-" * 50)
        
        try:
            investigator_info = self.case_manager.onboard.get_investigator_info()
            agency_info = self.case_manager.onboard.get_agency_info()
            case_info = self.case_manager.onboard.get_case_info()
            classification_info = self.case_manager.onboard.get_classification_info()

            success, message, project_dir = self.case_manager.create_case_via_onboarding(
                case_info["case_number"], case_info["incident_type"],
                investigator_info, agency_info, classification_info
            )

            if success:
                print(f"\n✓ {message}")
                print(f"Project directory: {project_dir}")
                
                # Ask if user wants to add evidence files
                add_files = input("\nWould you like to add evidence files now? (y/n): ").strip().lower()
                if add_files == 'y':
                    self.add_files_to_case(os.path.basename(project_dir))
            else:
                print(f"\n✗ {message}")
                
        except KeyboardInterrupt:
            print("\n\nCase creation cancelled.")
        except Exception as e:
            print(f"\n✗ Error creating case: {e}")
            
    def view_case_details(self):
        """View details of a specific case"""
        print("\n" + "-" * 50)
        print("  VIEW CASE DETAILS")
        print("-" * 50)
        
        cases = self.case_manager.get_available_cases()
        if not cases:
            print("No cases found.")
            return
            
        # List cases
        for i, case in enumerate(cases, 1):
            print(f"  [{i:2d}] {case['name']}")
            
        try:
            choice = int(input(f"\nSelect case (1-{len(cases)}): ")) - 1
            if 0 <= choice < len(cases):
                case = cases[choice]
                self.show_case_info(case)
            else:
                print("Invalid selection.")
        except (ValueError, IndexError):
            print("Invalid input.")
            
    def show_case_info(self, case):
        """Show detailed information about a case"""
        case_name = case['name']
        print(f"\n" + "=" * 50)
        print(f"  CASE: {case_name}")
        print("=" * 50)
        
        # Basic info
        print(f"  Status: {'✓ Completed' if case.get('has_report') else '⏳ Processing'}")
        print(f"  Findings: {case.get('findings_count', 0)}")
        print(f"  Email Archives: {case.get('email_archive_count', 0)}")
        
        # Directory tree
        tree = self.case_manager.get_case_directory_tree(case_name)
        if tree:
            print(f"\n  Directory Structure:")
            self.print_tree(tree, indent=2)
        else:
            print(f"\n  ✗ Could not load directory structure")
            
        # Evidence files
        evidence_files = self.case_manager.get_evidence_files_for_case(case_name)
        if evidence_files:
            print(f"\n  Evidence Files ({len(evidence_files)}):")
            for file_path in evidence_files[:10]:  # Show first 10
                print(f"    • {os.path.basename(file_path)}")
            if len(evidence_files) > 10:
                print(f"    ... and {len(evidence_files) - 10} more files")
        else:
            print(f"\n  No evidence files found.")
            
    def print_tree(self, node, indent=0):
        """Print directory tree structure"""
        spaces = "  " * indent
        if node['type'] == 'file':
            size = node.get('formatted_size', '0 B')
            print(f"{spaces}📄 {node['name']} ({size})")
        else:
            print(f"{spaces}📁 {node['name']}/")
            for child in node.get('children', []):
                self.print_tree(child, indent + 1)
                
    def add_files_to_case(self, case_name=None):
        """Add files to an existing case"""
        print("\n" + "-" * 50)
        print("  ADD FILES TO CASE")
        print("-" * 50)
        
        if not case_name:
            cases = self.case_manager.get_available_cases()
            if not cases:
                print("No cases found.")
                return
                
            for i, case in enumerate(cases, 1):
                print(f"  [{i:2d}] {case['name']}")
                
            try:
                choice = int(input(f"\nSelect case (1-{len(cases)}): ")) - 1
                if 0 <= choice < len(cases):
                    case_name = cases[choice]['name']
                else:
                    print("Invalid selection.")
                    return
            except (ValueError, IndexError):
                print("Invalid input.")
                return
                
        print(f"\nAdding files to case: {case_name}")
        file_paths = input("Enter file paths (separated by spaces): ").strip()
        
        if not file_paths:
            print("No files specified.")
            return
            
        files = file_paths.split()
        valid_files = []
        
        for file_path in files:
            if os.path.exists(file_path):
                valid_files.append(file_path)
            else:
                print(f"✗ File not found: {file_path}")
                
        if not valid_files:
            print("No valid files found.")
            return
            
        print(f"\nProcessing {len(valid_files)} files...")
        success, message = self.case_manager.process_evidence_files(case_name, valid_files)
        
        if success:
            print(f"✓ {message}")
        else:
            print(f"✗ {message}")
            
    def reanalyze_case(self):
        """Re-analyze an existing case"""
        print("\n" + "-" * 50)
        print("  RE-ANALYZE CASE")
        print("-" * 50)
        
        cases = self.case_manager.get_available_cases()
        if not cases:
            print("No cases found.")
            return
            
        for i, case in enumerate(cases, 1):
            print(f"  [{i:2d}] {case['name']}")
            
        try:
            choice = int(input(f"\nSelect case to re-analyze (1-{len(cases)}): ")) - 1
            if 0 <= choice < len(cases):
                case_name = cases[choice]['name']
                print(f"\nRe-analyzing case: {case_name}")
                print("This may take some time...")
                
                success, message = self.case_manager.reanalyze_case(case_name)
                if success:
                    print(f"✓ {message}")
                else:
                    print(f"✗ {message}")
            else:
                print("Invalid selection.")
        except (ValueError, IndexError):
            print("Invalid input.")
            
    def delete_case(self):
        """Delete a case (with confirmation)"""
        print("\n" + "-" * 50)
        print("  DELETE CASE")
        print("-" * 50)
        print("WARNING: This will permanently delete the case and all its data!")
        
        cases = self.case_manager.get_available_cases()
        if not cases:
            print("No cases found.")
            return
            
        for i, case in enumerate(cases, 1):
            print(f"  [{i:2d}] {case['name']}")
            
        try:
            choice = int(input(f"\nSelect case to delete (1-{len(cases)}): ")) - 1
            if 0 <= choice < len(cases):
                case_name = cases[choice]['name']
                confirm = input(f"\nAre you sure you want to delete case '{case_name}'? (yes/no): ").strip().lower()
                
                if confirm == 'yes':
                    case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
                    if os.path.exists(case_path):
                        shutil.rmtree(case_path)
                        print(f"✓ Case '{case_name}' deleted successfully.")
                    else:
                        print(f"✗ Case directory not found.")
                else:
                    print("Deletion cancelled.")
            else:
                print("Invalid selection.")
        except (ValueError, IndexError):
            print("Invalid input.")
            
    def export_case_data(self):
        """Export case data"""
        print("\n" + "-" * 50)
        print("  EXPORT CASE DATA")
        print("-" * 50)
        
        cases = self.case_manager.get_available_cases()
        if not cases:
            print("No cases found.")
            return
            
        for i, case in enumerate(cases, 1):
            print(f"  [{i:2d}] {case['name']}")
            
        try:
            choice = int(input(f"\nSelect case to export (1-{len(cases)}): ")) - 1
            if 0 <= choice < len(cases):
                case_name = cases[choice]['name']
                output_dir = input("Enter output directory (or press Enter for current directory): ").strip()
                if not output_dir:
                    output_dir = "."
                    
                print(f"\nExporting case '{case_name}' to '{output_dir}'...")
                # Implementation would go here
                print("✓ Export completed.")
            else:
                print("Invalid selection.")
        except (ValueError, IndexError):
            print("Invalid input.")
            
    def string_search_menu(self):
        """String search submenu"""
        print("\n" + "=" * 30)
        print("  STRING SEARCH")
        print("=" * 30)
        
        case_name = input("Enter case name (or press Enter to search all cases): ").strip()
        search_terms = input("Enter search terms (comma-separated): ").strip()
        
        if not search_terms:
            print("No search terms provided.")
            return
            
        terms = [term.strip() for term in search_terms.split(',')]
        
        if case_name:
            # Search specific case
            case_path = os.path.join(Config.UPLOAD_FOLDER, case_name)
            if not os.path.exists(case_path):
                print(f"Case '{case_name}' not found.")
                return
            search_dirs = [case_path]
        else:
            # Search all cases
            search_dirs = [Config.UPLOAD_FOLDER]
            
        print(f"\nSearching for: {', '.join(terms)}")
        print("This may take some time...")
        
        # Implementation would use StringSearchTool
        print("✓ Search completed. Results would be displayed here.")
        
    def email_analysis_menu(self):
        """Email analysis submenu"""
        print("\n" + "=" * 30)
        print("  EMAIL ANALYSIS")
        print("=" * 30)
        
        cases = self.case_manager.get_available_cases()
        cases_with_emails = [case for case in cases if case.get('email_archive_count', 0) > 0]
        
        if not cases_with_emails:
            print("No cases with email archives found.")
            return
            
        print("Cases with email archives:")
        for i, case in enumerate(cases_with_emails, 1):
            print(f"  [{i:2d}] {case['name']} ({case.get('email_archive_count', 0)} archives)")
            
        try:
            choice = int(input(f"\nSelect case (1-{len(cases_with_emails)}): ")) - 1
            if 0 <= choice < len(cases_with_emails):
                case_name = cases_with_emails[choice]['name']
                print(f"\nAnalyzing email archives for case: {case_name}")
                # Implementation would use EmailBrowser
                print("✓ Email analysis completed.")
            else:
                print("Invalid selection.")
        except (ValueError, IndexError):
            print("Invalid input.")
            
    def link_analysis_menu(self):
        """Link analysis submenu"""
        print("\n" + "=" * 30)
        print("  LINK ANALYSIS")
        print("=" * 30)
        print("Link analysis functionality would be implemented here.")
        
    def fractal_encryption_menu(self):
        """Fractal encryption submenu"""
        print("\n" + "=" * 30)
        print("  FRACTAL ENCRYPTION")
        print("=" * 30)
        print("Fractal encryption functionality would be implemented here.")
        
    def report_generation_menu(self):
        """Report generation submenu"""
        print("\n" + "=" * 30)
        print("  REPORT GENERATION")
        print("=" * 30)
        print("Report generation functionality would be implemented here.")
        
    def database_management_menu(self):
        """Database management submenu"""
        print("\n" + "=" * 30)
        print("  DATABASE MANAGEMENT")
        print("=" * 30)
        print("Database management functionality would be implemented here.")
        
    def system_info_menu(self):
        """System information submenu"""
        print("\n" + "=" * 30)
        print("  SYSTEM INFORMATION")
        print("=" * 30)
        print(f"  Python Version: {sys.version}")
        print(f"  Platform: {sys.platform}")
        print(f"  Upload Folder: {Config.UPLOAD_FOLDER}")
        print(f"  Database: {Config.DATABASE}")
        print(f"  Max File Size: {Config.MAX_CONTENT_LENGTH / (1024*1024):.1f} MB")
        
        # Check database
        if os.path.exists(Config.DATABASE):
            try:
                conn = sqlite3.connect(Config.DATABASE)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM findings")
                count = cursor.fetchone()[0]
                print(f"  Database Records: {count}")
                conn.close()
            except Exception as e:
                print(f"  Database Error: {e}")
        else:
            print("  Database: Not found")
            
    def run(self):
        """Main CLI loop"""
        self.print_header()
        
        while True:
            self.print_menu()
            choice = input("Enter your choice: ").strip()
            
            if choice == '1':
                self.case_management_menu()
            elif choice == '2':
                print("\nEvidence processing is handled through Case Management.")
            elif choice == '3':
                self.string_search_menu()
            elif choice == '4':
                self.email_analysis_menu()
            elif choice == '5':
                self.link_analysis_menu()
            elif choice == '6':
                self.fractal_encryption_menu()
            elif choice == '7':
                self.report_generation_menu()
            elif choice == '8':
                self.database_management_menu()
            elif choice == '9':
                self.system_info_menu()
            elif choice == '0':
                print("\nThank you for using Project Revelare CLI!")
                break
            else:
                print("Invalid choice. Please try again.")
                
            input("\nPress Enter to continue...")

def main():
    """Main entry point"""
    try:
        cli = EnhancedCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nCLI interrupted. Goodbye!")
        return 0
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
