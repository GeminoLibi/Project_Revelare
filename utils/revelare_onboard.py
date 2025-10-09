"""
Project Revelare - Onboarding Utility and Metadata Structure
"""

import os
import sys
import json
import glob
import shutil
import datetime 
from typing import Dict, List, Optional, Any
from pathlib import Path
import subprocess

from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator
from revelare.config.config import Config

onboard_logger = RevelareLogger.get_logger('onboarding')

class RevelareMetadata:
    
    INCIDENT_TYPES = [
        "Homicide", "Assault", "Battery", "Robbery", "Armed Robbery", "Carjacking", "Kidnapping", "Domestic Violence", "Sexual Assault", "Rape", "Child Abuse", "Elder Abuse", "Stalking", "Threats", "Terrorism", "Mass Shooting", "Active Shooter", 
        "Burglary", "Theft", "Auto Theft", "Grand Theft", "Petty Theft", "Vandalism", "Graffiti", "Arson", "Fraud", "Identity Theft", "Credit Card Fraud", "Check Fraud", "Embezzlement", "Forgery", "Counterfeiting", 
        "Drug Possession", "Drug Trafficking", "Drug Manufacturing", "Drug Distribution", "DUI/DWI", "Public Intoxication", "Drug Paraphernalia", 
        "Hit and Run", "Reckless Driving", "Driving Without License", "Speeding", "Traffic Violation", "Fatal Accident", "Injury Accident", 
        "Cyber Crime", "Computer Fraud", "Online Harassment", "Cyber Stalking", "Revenge Porn", "Sextortion", "Online Child Exploitation", "Dark Web Activity", "Cryptocurrency Crime", "Social Media Crime", 
        "Money Laundering", "Tax Evasion", "Insurance Fraud", "Securities Fraud", "Corporate Crime", "Public Corruption", "Bribery", "Extortion", "Racketeering", 
        "Disorderly Conduct", "Public Nuisance", "Trespassing", "Loitering", "Disturbing the Peace", "Resisting Arrest", "Obstruction of Justice", "Contempt of Court", "Probation Violation", "Parole Violation", 
        "Missing Person", "Runaway Juvenile", "Missing Adult", "Amber Alert", "Silver Alert", 
        "Warrant Service", "Search Warrant", "Arrest Warrant", "Civil Process", "Court Order", "Protection Order", "Restraining Order", "Mental Health Hold", "Welfare Check", "Death Investigation", "Suicide", "Accidental Death", "Suspicious Death", "Unattended Death", 
        "Gang Activity", "Organized Crime", "Human Trafficking", "Prostitution", "Gambling", "Weapons Violation", "Illegal Firearms", "Explosives", "Bomb Threat", "Suspicious Package", 
        "Other"
    ]
    
    AGENCIES = [
        "FBI", "CISA", "NSA", "DHS", "DOJ", "Secret Service", "DEA", "ATF", "ICE", "US Marshals", "US Postal Inspection", "Treasury Inspector General", 
        "State Police", "State Bureau of Investigation", "Highway Patrol", "State Attorney General", "State Fire Marshal", "State Gaming Commission", 
        "County Sheriff's Office", "County Police", "County District Attorney", "County Coroner", "County Probation", "County Parole", 
        "City Police Department", "Town Police Department", "Village Police Department", "Campus Police", "Transit Police", "Harbor Police", "Airport Police", 
        "SWAT Team", "K-9 Unit", "Detective Bureau", "Crime Scene Unit", "Forensic Unit", "Cyber Crimes Unit", "Narcotics Unit", "Gang Unit", "Vice Unit", "Homicide Unit", "Sex Crimes Unit", "Child Abuse Unit", "Elder Abuse Unit", "Domestic Violence Unit", "Traffic Unit", "Patrol Division", 
        "Private Security Firm", "Corporate Security", "Academic Institution Security", "Military Police", "Military Criminal Investigation", "Coast Guard", "Border Patrol", "Customs and Border Protection", 
        "Other"
    ]
    
    CLASSIFICATIONS = ["Unclassified", "Confidential", "Secret", "Top Secret", "Law Enforcement Sensitive"]


class RevelareOnboard:

    def __init__(self):
        self.log = onboard_logger
        self.metadata = RevelareMetadata()
        self.case_details: Dict[str, Any] = {}

    def _get_validated_input(self, prompt: str, required: bool = True) -> str:
        while True:
            value = input(prompt).strip()
            if required and not value:
                print("❌ This field is required.")
                continue
            return value

    def _get_choice_from_list(self, list_options: List[str], prompt_name: str) -> str:
        print(f"\nSelect {prompt_name}:")
        for i, item in enumerate(list_options, 1):
            print(f"  {i:2d}. {item}")
        
        while True:
            try:
                choice = int(input(f"\n{prompt_name} (1-{len(list_options)}): "))
                if 1 <= choice <= len(list_options):
                    return list_options[choice - 1]
                else:
                    print(f"❌ Invalid choice. Please select 1-{len(list_options)}")
            except ValueError:
                print("❌ Please enter a valid number")

    def display_header(self):
        print("=" * 60)
        print("Project Revelare - Case Onboarding")
        print("=" * 60)

    def get_investigator_info(self) -> Dict[str, str]:
        print("\n[INVESTIGATOR INFORMATION]")
        print("-" * 30)
        return {
            "name": self._get_validated_input("Investigator Name: "),
            "id": self._get_validated_input("Investigator ID/Badge Number (optional): ", required=False),
            "email": self._get_validated_input("Investigator Email (optional): ", required=False)
        }

    def get_agency_info(self) -> Dict[str, str]:
        print("\n[AGENCY INFORMATION]")
        print("-" * 30)
        selected_agency = self._get_choice_from_list(self.metadata.AGENCIES, "Agency")
        agency_name = self._get_validated_input(f"Agency Name (if different, default '{selected_agency}'): ", required=False) or selected_agency
        jurisdiction = self._get_validated_input("Jurisdiction (e.g., 'Federal', 'State of CA'): ", required=False)
        
        return {"agency": selected_agency, "name": agency_name, "jurisdiction": jurisdiction}

    def get_case_info(self) -> Dict[str, str]:
        print("\n[CASE INFORMATION]")
        print("-" * 30)
        case_number = self._get_validated_input("Case Number: ")
        selected_incident = self._get_choice_from_list(self.metadata.INCIDENT_TYPES, "Incident Type")
        incident_description = self._get_validated_input("Incident Description (optional): ", required=False)
        incident_date = self._get_validated_input("Incident Date (YYYY-MM-DD, optional, default Today): ", required=False)
        
        # Date validation and assignment
        if not incident_date:
            incident_date = datetime.datetime.now().strftime('%Y-%m-%d')
        else:
            try:
                datetime.datetime.strptime(incident_date, '%Y-%m-%d')
            except ValueError:
                print("❌ Invalid date format. Using current date.")
                incident_date = datetime.datetime.now().strftime('%Y-%m-%d')
        
        return {
            "case_number": case_number,
            "incident_type": selected_incident,
            "description": incident_description,
            "incident_date": incident_date,
            "created_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def get_classification_info(self) -> Dict[str, str]:
        print("\n[CLASSIFICATION]")
        print("-" * 30)
        selected_classification = self._get_choice_from_list(self.metadata.CLASSIFICATIONS, "Classification Level")
        retention_period = self._get_validated_input("Retention Period (e.g., '7 years', 'Permanent', optional): ", required=False)
        
        return {"level": selected_classification, "retention_period": retention_period}
        
    # --- Project Setup and Staging ---

    def create_project_structure(self, case_info: Dict) -> str:
        print("\n[PROJECT STRUCTURE]")
        print("-" * 30)
        # Hardened project name generation
        case_number = SecurityValidator.sanitize_filename(case_info["case_number"].replace(" ", "_"))
        incident_type = SecurityValidator.sanitize_filename(case_info["incident_type"].replace(" ", "_"))
        project_name = f"{case_number}_{incident_type}_{datetime.datetime.now().strftime('%Y%m%d')}"
        
        from revelare.config.config import Config
        base_dir = Config.UPLOAD_FOLDER
        project_dir = os.path.join(base_dir, project_name)
        
        print(f"Project Name: {project_name}")
        
        subdirs = ["evidence", "analysis", "reports", "exports", "logs", "archive"]
        
        Path(project_dir).mkdir(parents=True, exist_ok=True)
        for subdir in subdirs:
            Path(os.path.join(project_dir, subdir)).mkdir(exist_ok=True)
        
        self.log.info(f"Project structure created: {project_dir}")
        print(f"Project Directory: {project_dir}")
        return project_dir

    def save_case_metadata(self, project_dir: str, **kwargs: Dict):
        metadata = {"case_metadata": kwargs}
        
        # CRITICAL FIX: Ensure ALLOWED_EXTENSIONS is correctly flattened (Fixes TypeError: 'set' object has no attribute 'values')
        supported_formats_list = []
        if isinstance(Config.ALLOWED_EXTENSIONS, dict):
            for exts in Config.ALLOWED_EXTENSIONS.values():
                 if isinstance(exts, (list, set, tuple)):
                     supported_formats_list.extend(exts)
                 else:
                      supported_formats_list.append(exts)
        else:
             self.log.error("Config.ALLOWED_EXTENSIONS is not a dictionary. Cannot save supported formats metadata.")

        metadata["processing_info"] = {
            "revelare_version": "2.3 (Tuned)",
            "max_file_size_mb": Config.MAX_CONTENT_LENGTH // (1024 * 1024),
            "supported_formats": supported_formats_list
        }
        
        metadata_file = os.path.join(project_dir, "case_metadata.json")
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        print(f"\n[OK] Case metadata saved: {metadata_file}")

    def get_evidence_files(self, project_dir: str) -> List[str]:
        print("\n[EVIDENCE FILES]")
        print("-" * 30)
        print("Enter source file paths (supports wildcards * and ?).")
        print("Files will be copied to the local 'evidence/' directory.")
        
        evidence_files_source = []
        evidence_dir = os.path.join(project_dir, "evidence")
        
        # Loop for collecting paths
        while True:
            file_input = input("Evidence file path (or 'done'): ").strip()
            if file_input.lower() == 'done' or not file_input: break
                
            if '*' in file_input or '?' in file_input:
                expanded_files = glob.glob(file_input)
                if expanded_files:
                    evidence_files_source.extend(expanded_files)
                    print(f"[OK] Found {len(expanded_files)} files matching pattern")
                else:
                    print("[ERROR] No files found matching pattern")
            elif os.path.exists(file_input):
                if os.path.isfile(file_input):
                    evidence_files_source.append(file_input)
                    print(f"[OK] Added file: {file_input}")
                elif os.path.isdir(file_input):
                    # Expand directory to all files within it
                    dir_files = []
                    for root, dirs, files in os.walk(file_input):
                        for file in files:
                            full_path = os.path.join(root, file)
                            dir_files.append(full_path)

                    if dir_files:
                        evidence_files_source.extend(dir_files)
                        print(f"[OK] Added directory: {file_input} ({len(dir_files)} files)")
                    else:
                        print(f"[WARNING] Directory is empty: {file_input}")
                else:
                    print(f"[ERROR] Path exists but is neither file nor directory: {file_input}")
            else:
                print(f"[ERROR] File not found: {file_input}")
        
        # Copy files to evidence directory and rename if duplicates exist
        new_evidence_paths = []
        if evidence_files_source:
            self.log.info(f"Copying {len(evidence_files_source)} files to {evidence_dir}")
            
            for i, file_path in enumerate(evidence_files_source, 1):
                try:
                    # Sanitize filename and handle duplicate names robustly
                    filename = os.path.basename(file_path)
                    name, ext = os.path.splitext(filename)
                    dest_path = os.path.join(evidence_dir, filename)
                    
                    # Deduplication loop
                    counter = 1
                    while os.path.exists(dest_path):
                        dest_path = os.path.join(evidence_dir, f"{name}_{counter}{ext}")
                        counter += 1
                        
                    shutil.copy2(file_path, dest_path)
                    new_evidence_paths.append(dest_path)
                    print(f"  [{i:2d}] {filename} -> {os.path.basename(dest_path)}")
                except Exception as e:
                    self.log.error(f"Failed to copy {file_path}: {e}")
        
        return new_evidence_paths

    def generate_processing_script(self, project_dir: str, project_name: str, evidence_files: List[str]):
        script_content = f'''#!/usr/bin/env python3
"""
Auto-generated processing script for case: {project_name}
Generated by Project Revelare Onboarding (v2.3)
"""

import os
import sys
from pathlib import Path
import glob
import subprocess

# NOTE: Assumes revelare_cli.py is in the current working directory.
# This script is designed to be run from inside the project directory (e.g., /cases/CASE_XYZ/)
def main():
    """Process evidence files for case: {project_name}"""
    
    # Define paths relative to the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    evidence_dir = os.path.join(script_dir, "evidence")
    analysis_dir = os.path.join(script_dir, "analysis")
    
    # Collect all files in the evidence directory
    evidence_files_in_dir = [str(p) for p in Path(evidence_dir).glob('*') if p.is_file()]

    if not evidence_files_in_dir:
        print("❌ No evidence files found in evidence/ directory")
        print("Please place your evidence files in the evidence/ directory and run this script again")
        return 1
    
    # We must construct the path to revelare_cli.py based on where the script is run from.
    # Assuming CLI is one level up (standard structure)
    cli_path = os.path.join(script_dir, '..', 'revelare_cli.py')

    # Prepare the arguments for subprocess call
    cli_command = [
        sys.executable, cli_path,
        "--project", "{project_name}", 
        "--output", analysis_dir,
        "--files", *evidence_files_in_dir
    ]
    
    # CRITICAL FIX (NameError): The host function used the len() of evidence_files. 
    # Here, we use the len() of the list *passed to the function* to correctly display the count.
    print(f"Running processing command:")
    print("-" * 60)
    print(f"python revelare_cli.py -p \\"{project_name}\\" -o analysis/ -f <{len(evidence_files_in_dir)} files>")
    print("-" * 60)
    
    # Execute the CLI using subprocess for isolation
    try:
        # NOTE: Using subprocess.run for safer, isolated CLI execution
        result = subprocess.run(cli_command, check=True, capture_output=True, text=True)
        print("\\n" + result.stdout)
        print("\\n✅ Case processing completed successfully!")
        print(f"📁 Check the analysis/ directory for results: {analysis_dir}")
        return 0
    except subprocess.CalledProcessError as e:
        print("\\n❌ Case processing failed (Exit Code 1).")
        print(f"Output: {e.stdout}")
        print(f"Error: {e.stderr}")
        return 1
    except FileNotFoundError:
        print(f"❌ Error: Python executable not found or cli path is wrong: {cli_path}")
        return 1

if __name__ == "__main__":
    main()
'''
        
        script_file = os.path.join(project_dir, "process_case.py")
        with open(script_file, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        print(f"[OK] Processing script created: {script_file}")

    def display_next_steps(self, project_dir: str, project_name: str):
        print("\n" + "=" * 60)
        print("ONBOARDING COMPLETE")
        print("=" * 60)
        print(f"\nProject Directory: {project_dir}")
        print("\nNext Steps:")
        print("   1. Place evidence files in the 'evidence/' directory")
        print("   2. Run the generated processing script from inside the project directory:")
        print(f"      cd {project_dir}")
        print("      python process_case.py")
        print("\nOutput will be saved to the 'analysis/' subdirectory.")

    def run_complete_maestro(self, process_evidence: bool = True):
        try:
            self.display_header()
            investigator_info = self.get_investigator_info()
            agency_info = self.get_agency_info()
            case_info = self.get_case_info()
            classification_info = self.get_classification_info()
            
            project_dir = self.create_project_structure(case_info)
            project_name = os.path.basename(project_dir)
            
            # FIX 1: Save metadata BEFORE calling get_evidence_files
            self.save_case_metadata(project_dir, investigator_info=investigator_info, agency_info=agency_info, case_info=case_info, classification_info=classification_info)
            
            # FIX 2: evidence_files must be a variable in the local scope
            evidence_files = [] 
            
            if process_evidence:
                evidence_files = self.get_evidence_files(project_dir)
                
            # FIX 3: Pass the required evidence_files list to the script generator
            self.generate_processing_script(project_dir, project_name, evidence_files)
            
            if process_evidence:
                if evidence_files:
                    print("\nStarting immediate evidence processing via generated script...")
                    print("\n[INFO] Processing delegated to generated script: **python process_case.py**")
                    return 0
                else:
                    self.display_next_steps(project_dir, project_name)
                    return 0
            else:
                self.display_next_steps(project_dir, project_name)
                return 0
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Process interrupted by user")
            return 1
        except Exception as e:
            print(f"\n❌ Error during process: {e}")
            self.log.error(f"Maestro process error: {e}")
            return 1

    def run_onboarding(self):
        return self.run_complete_maestro(process_evidence=False)


if __name__ == "__main__":
    # NOTE: Execution block for revelare_onboard.py itself
    onboard = RevelareOnboard()
    try:
        sys.exit(onboard.run_complete_maestro(process_evidence=True))
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        print(f"❌ Critical error in onboard main: {e}")
        sys.exit(1)