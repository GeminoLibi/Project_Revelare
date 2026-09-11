"""Shared findings and report artifacts for CLI and web.

CLI historically wrote indicators.json / {case}_report.html.
Web historically wrote raw_findings.json / report.html.
Both sides now read either name and write both so status and findings stay in sync.
No vault copies are required: findings JSON/CSV plus SourcePath is enough.
"""
import csv
import json
import os
from typing import Any, Dict, Optional

FINDINGS_JSON_NAMES = ("raw_findings.json", "indicators.json")
FINDINGS_CSV_NAME = "indicators.csv"
CANONICAL_REPORT = "report.html"


def count_findings(findings: Optional[Dict[str, Any]]) -> int:
    if not findings:
        return 0
    total = 0
    for key, items in findings.items():
        if key == "Processing_Summary" or not isinstance(items, dict):
            continue
        total += len(items)
    return total


def findings_json_path(case_path: str) -> Optional[str]:
    if not case_path:
        return None
    for name in FINDINGS_JSON_NAMES:
        path = os.path.join(case_path, name)
        if os.path.isfile(path):
            return path
    return None


def load_findings(case_path: str) -> Optional[Dict[str, Any]]:
    path = findings_json_path(case_path)
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return None
    return data


def has_findings_artifacts(case_path: str) -> bool:
    if findings_json_path(case_path):
        return True
    csv_path = os.path.join(case_path, FINDINGS_CSV_NAME)
    return os.path.isfile(csv_path)


def report_html_path(case_path: str, case_name: Optional[str] = None) -> Optional[str]:
    if not case_path or not os.path.isdir(case_path):
        return None
    candidates = [os.path.join(case_path, CANONICAL_REPORT)]
    if case_name:
        candidates.append(os.path.join(case_path, "%s_report.html" % case_name))
    for path in candidates:
        if os.path.isfile(path):
            return path
    try:
        for name in os.listdir(case_path):
            if name.endswith("_report.html"):
                return os.path.join(case_path, name)
    except OSError:
        return None
    return None


def case_processing_complete(case_path: str, case_name: Optional[str] = None) -> bool:
    """True when CLI or web already produced findings or a report. No vault required."""
    if has_findings_artifacts(case_path):
        return True
    return report_html_path(case_path, case_name) is not None


def write_findings_artifacts(case_path: str, findings: Dict[str, Any]) -> None:
    os.makedirs(case_path, exist_ok=True)
    raw_path = os.path.join(case_path, "raw_findings.json")
    with open(raw_path, "w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2, ensure_ascii=False)

    enhanced = {
        key: value
        for key, value in findings.items()
        if key != "Processing_Summary" and isinstance(value, dict)
    }
    json_path = os.path.join(case_path, "indicators.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(enhanced, handle, indent=2, ensure_ascii=False)

    from revelare.core.source_ingest import parse_source_fields

    csv_path = os.path.join(case_path, FINDINGS_CSV_NAME)
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Category", "Indicator", "SourcePath", "SourceHash", "Context"])
        for category, items in enhanced.items():
            if not items:
                continue
            for indicator, context in items.items():
                source_path, source_hash = parse_source_fields(context)
                safe_context = str(context).replace("\n", " ")[:250]
                writer.writerow([category, indicator, source_path, source_hash, safe_context])


def write_report_html(case_path: str, project_name: str, html: str) -> None:
    os.makedirs(case_path, exist_ok=True)
    for name in (CANONICAL_REPORT, "%s_report.html" % project_name):
        with open(os.path.join(case_path, name), "w", encoding="utf-8") as handle:
            handle.write(html)


def parse_indicator_context(context: Any) -> Dict[str, str]:
    context_str = str(context or "")
    file_source = "Unknown"
    position = "N/A"
    if "File:" in context_str:
        file_source = context_str.split("File:")[1].split("|")[0].strip()
    if "Position:" in context_str:
        position = context_str.split("Position:")[1].split("|")[0].strip()
    from revelare.core.source_ingest import parse_source_fields
    source_path, source_hash = parse_source_fields(context_str)
    if source_path and file_source == "Unknown":
        file_source = os.path.basename(source_path.replace("!", os.sep))
    return {
        "file": file_source,
        "position": position,
        "source_path": source_path,
        "source_hash": source_hash,
        "details": context_str,
    }
