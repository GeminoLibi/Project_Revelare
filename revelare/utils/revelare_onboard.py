import os
import sys
import json
import glob
import shutil
import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from revelare.utils.logger import get_logger, RevelareLogger
from revelare.utils.security import SecurityValidator
from revelare.config.config import Config

onboard_logger = RevelareLogger.get_logger('onboarding')

class RevelareMetadata:
    INCIDENT_TYPES = [
        "Homicide", "Assault", "Robbery", "Kidnapping", "Domestic Violence", "Sexual Assault", 
        "Burglary", "Theft", "Fraud", "Identity Theft", "Cyber Crime", "Drug Trafficking", 
        "Financial Crime", "Public Corruption", "Missing Person", "Terrorism", "Other"
    ]
    AGENCIES = [
        "FBI", "CISA", "NSA", "DHS", "Secret Service", "DEA", "State Police", 
        "County Sheriff's Office", "City Police Department", "Other"
    ]
    CLASSIFICATIONS = ["Unclassified", "Confidential", "Secret", "Top Secret", "Law Enforcement Sensitive"]

class RevelareOnboard:
    def __init__(self):
        self.log = onboard_logger
        self.metadata = RevelareMetadata()

    def _get_validated_input(self, prompt: str, required: bool = True) -> str:
        while True:
            value = input(prompt).strip()
            if required and not value:
                print("This field is required.")
                continue
            return value

    def _get_choice_from_list(self, list_options: List[str], prompt_name: str) -> str:
        print(f"\nSelect {prompt_name}:")
        for i, item in enumerate(list_options, 1):
            print(f"  {i:2d}. {item}")
        
        while True:
            try:
                choice = int(input(f"\n{prompt_name} (1-{len(list_options)}): "))
                if 1 <= choice <= len(list_options):
                    return list_options[choice - 1]
                else:
                    print(f"Invalid choice. Please select 1-{len(list_options)}")
            except ValueError:
                print("Please enter a valid number.")

    def get_investigator_info(self) -> Dict[str, str]:
        print("\n[INVESTIGATOR INFORMATION]")
        return {
            "name": self._get_validated_input("Investigator Name: "),
            "id": self._get_validated_input("Investigator ID/Badge Number (optional): ", required=False),
            "email": self._get_validated_input("Investigator Email (optional): ", required=False)
        }

    def get_agency_info(self) -> Dict[str, str]:
        print("\n[AGENCY INFORMATION]")
        selected_agency = self._get_choice_from_list(self.metadata.AGENCIES, "Agency")
        agency_name = self._get_validated_input(f"Agency Name (default: '{selected_agency}'): ", required=False) or selected_agency
        jurisdiction = self._get_validated_input("Jurisdiction: ", required=False)
        
        return {"agency": selected_agency, "name": agency_name, "jurisdiction": jurisdiction}

    def get_case_info(self) -> Dict[str, str]:
        print("\n[CASE INFORMATION]")
        case_number = self._get_validated_input("Case Number: ")
        selected_incident = self._get_choice_from_list(self.metadata.INCIDENT_TYPES, "Incident Type")
        incident_description = self._get_validated_input("Incident Description (optional): ", required=False)
        
        return {
            "case_number": case_number,
            "incident_type": selected_incident,
            "description": incident_description,
            "created_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def get_classification_info(self) -> Dict[str, str]:
        print("\n[CLASSIFICATION]")
        selected_classification = self._get_choice_from_list(self.metadata.CLASSIFICATIONS, "Classification Level")
        retention_period = self._get_validated_input("Retention Period (optional): ", required=False)
        
        return {"level": selected_classification, "retention_period": retention_period}
        
    def create_project_structure(self, case_info: Dict) -> str:
        case_number_safe = SecurityValidator.sanitize_filename(case_info["case_number"].replace(" ", "_"))
        incident_type_safe = SecurityValidator.sanitize_filename(case_info["incident_type"].replace(" ", "_"))
        project_name = f"{case_number_safe}_{incident_type_safe}_{datetime.datetime.now().strftime('%Y%m%d')}"
        
        project_dir = os.path.join(Config.UPLOAD_FOLDER, project_name)
        
        subdirs = ["evidence", "analysis", "reports", "exports", "logs"]
        
        Path(project_dir).mkdir(parents=True, exist_ok=True)
        for subdir in subdirs:
            Path(os.path.join(project_dir, subdir)).mkdir(exist_ok=True)
        
        self.log.info(f"Project structure created: {project_dir}")
        return project_dir

    def save_case_metadata(self, project_dir: str, **kwargs: Dict):
        metadata = {"case_metadata": kwargs}
        
        supported_formats_list = []
        if isinstance(Config.ALLOWED_EXTENSIONS, dict):
            for exts in Config.ALLOWED_EXTENSIONS.values():
                 if isinstance(exts, (list, set, tuple)):
                     supported_formats_list.extend(exts)
        
        metadata["processing_info"] = {
            "revelare_version": "2.5",
            "supported_formats": supported_formats_list
        }
        
        metadata_file = os.path.join(project_dir, "case_metadata.json")
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)

    def get_evidence_files(self, project_dir: str) -> List[str]:
        print("\n[EVIDENCE FILES]")
        print("Enter source file paths (wildcards * and ? are supported).")
        
        evidence_files_source = []
        evidence_dir = os.path.join(project_dir, "evidence")
        
        while True:
            file_input = input("Evidence file path (or 'done'): ").strip()
            if file_input.lower() == 'done' or not file_input: break
                
            expanded_files = glob.glob(file_input, recursive=True)
            if expanded_files:
                evidence_files_source.extend(expanded_files)
                print(f"Added {len(expanded_files)} file(s) matching pattern.")
            else:
                print("No files found matching that path or pattern.")
        
        new_evidence_paths = []
        if evidence_files_source:
            self.log.info(f"Copying {len(evidence_files_source)} files to {evidence_dir}")
            
            for i, file_path in enumerate(evidence_files_source, 1):
                try:
                    if not os.path.isfile(file_path): continue
                    filename = os.path.basename(file_path)
                    dest_path = os.path.join(evidence_dir, filename)
                    
                    counter = 1
                    while os.path.exists(dest_path):
                        name, ext = os.path.splitext(filename)
                        dest_path = os.path.join(evidence_dir, f"{name}_{counter}{ext}")
                        counter += 1
                        
                    shutil.copy2(file_path, dest_path)
                    new_evidence_paths.append(dest_path)
                    print(f"  [{i:2d}] Copied {filename} -> {os.path.basename(dest_path)}")
                except Exception as e:
                    self.log.error(f"Failed to copy {file_path}: {e}")
        
        return new_evidence_paths