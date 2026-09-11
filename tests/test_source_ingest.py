#!/usr/bin/env python3
"""Smoke tests for temp-only ingest (no permanent document copies)."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class TestSourceIngest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp(prefix="revelare_ingest_test_")
        self.cases_dir = os.path.join(self.td, "cases")
        self.db_path = os.path.join(self.td, "test.db")
        os.makedirs(self.cases_dir, exist_ok=True)

        from revelare.config.config import Config

        self._orig_upload = Config.UPLOAD_FOLDER
        self._orig_db = Config.DATABASE
        Config.UPLOAD_FOLDER = self.cases_dir
        Config.DATABASE = self.db_path

        from revelare.core.database import init_database

        init_database()

        self.fixture = os.path.join(self.td, "sample_ioc.txt")
        with open(self.fixture, "w", encoding="ascii") as handle:
            handle.write("Revelare ingest smoke fixture. Contact: analyst@agency.gov IP: 203.0.113.50\n")

    def tearDown(self):
        from revelare.config.config import Config
        from revelare.core.source_ingest import clear_source_registry

        Config.UPLOAD_FOLDER = self._orig_upload
        Config.DATABASE = self._orig_db
        clear_source_registry()
        shutil.rmtree(self.td, ignore_errors=True)

    def test_stage_and_cleanup_keeps_original_only(self):
        from revelare.core.source_ingest import (
            clear_source_registry,
            sha256_file,
            stage_sources_to_temp,
        )

        temp_dir = os.path.join(self.td, "stage")
        os.makedirs(temp_dir, exist_ok=True)
        clear_source_registry()
        try:
            records = stage_sources_to_temp([self.fixture], temp_dir)
            self.assertEqual(len(records), 1)
            self.assertEqual(os.path.abspath(self.fixture), records[0]["source_path"])
            self.assertEqual(sha256_file(self.fixture), records[0]["source_hash"])
            staged = list(Path(temp_dir).rglob("*"))
            self.assertTrue(any(p.is_file() for p in staged))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            clear_source_registry()
        self.assertTrue(os.path.isfile(self.fixture))
        self.assertFalse(os.path.exists(temp_dir))

    def test_process_evidence_does_not_keep_vault_copy(self):
        from revelare.core.case_manager import CaseManager

        case_name = "SMOKE_Ingest_NoCopy"
        case_dir = os.path.join(self.cases_dir, case_name)
        for sub in ("evidence", "analysis", "reports", "exports", "logs"):
            os.makedirs(os.path.join(case_dir, sub), exist_ok=True)

        manager = CaseManager()
        ok, message = manager.process_evidence_files(case_name, [self.fixture], origin="local_path")
        self.assertTrue(ok, message)

        evidence_dir = os.path.join(case_dir, "evidence")
        extracted_dir = os.path.join(case_dir, "extracted_files")
        evidence_files = [
            p for p in Path(evidence_dir).rglob("*") if p.is_file()
        ] if os.path.isdir(evidence_dir) else []
        extracted_files = [
            p for p in Path(extracted_dir).rglob("*") if p.is_file()
        ] if os.path.isdir(extracted_dir) else []
        self.assertEqual(evidence_files, [], "ingest must not keep a copy in evidence/")
        self.assertEqual(extracted_files, [], "ingest must not keep a copy in extracted_files/")

        manifest_path = os.path.join(case_dir, "ingest_manifest.json")
        self.assertTrue(os.path.isfile(manifest_path))
        with open(manifest_path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertFalse(manifest.get("permanent_copies", True))
        self.assertEqual(manifest["files"][0]["source_path"], os.path.abspath(self.fixture))
        self.assertTrue(manifest["files"][0]["source_hash"])

        findings_path = os.path.join(case_dir, "raw_findings.json")
        self.assertTrue(os.path.isfile(findings_path))
        with open(findings_path, "r", encoding="utf-8") as handle:
            findings = json.load(handle)

        found_source = False
        for category, items in findings.items():
            if category == "Processing_Summary" or not isinstance(items, dict):
                continue
            for _value, context in items.items():
                if "SourcePath:" in str(context) and os.path.abspath(self.fixture) in str(context):
                    found_source = True
                    self.assertIn("SourceHash:", str(context))
        self.assertTrue(found_source, "findings must record SourcePath of the original file")
        self.assertTrue(os.path.isfile(self.fixture), "original source file must remain")

        from revelare.utils.file_extractor import get_script_temp_dir

        leftovers = []
        temp_base = get_script_temp_dir()
        if os.path.isdir(temp_base):
            leftovers = [
                name for name in os.listdir(temp_base)
                if name.startswith("revelare_%s" % case_name)
            ]
        self.assertEqual(leftovers, [], "temp processing copies must be deleted")


if __name__ == "__main__":
    unittest.main()
