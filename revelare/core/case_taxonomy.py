"""
Case taxonomy: incident types, tags, metadata helpers, and name-based inference.
"""
import json
import os
import re
from typing import Any, Dict, List, Optional, Set

from revelare.utils.logger import get_logger

logger = get_logger(__name__)

# Suggested tags at intake (users may add custom tags as comma-separated text)
CASE_TAGS = [
    "bond",
    "impersonation",
    "gov-impersonation",
    "romance",
    "bec",
    "crypto",
    "elder-fraud",
    "wire-fraud",
    "phone-fraud",
    "identity-theft",
    "cybercrime",
    "financial-crime",
    "subject",
    "victim",
    "closed",
    "active",
    "priority",
]

# Map tokens found in folder/case names to normalized tags
_TAG_INFERENCE = {
    "bond": "bond",
    "bondscam": "bond",
    "bond_scam": "bond",
    "imperson": "impersonation",
    "impers": "impersonation",
    "gov_impers": "gov-impersonation",
    "fakecops": "impersonation",
    "fraud": "financial-crime",
    "scam": "financial-crime",
    "romance": "romance",
    "bec": "bec",
    "crypto": "crypto",
    "bitcoin": "crypto",
    "elder": "elder-fraud",
    "wire": "wire-fraud",
    "phone": "phone-fraud",
    "identity": "identity-theft",
    "cyber": "cybercrime",
    "closed": "closed",
    "priority": "priority",
}

# Map tokens to incident types when metadata is missing
_INCIDENT_INFERENCE = {
    "bond": "Fraud",
    "fraud": "Fraud",
    "scam": "Fraud",
    "imperson": "Identity Theft",
    "impers": "Identity Theft",
    "cyber": "Cyber Crime",
    "homicide": "Homicide",
    "kidnap": "Kidnapping",
    "missing": "Missing Person",
    "terror": "Terrorism",
}


def normalize_tag(value: str) -> str:
    cleaned = value.strip().lower()
    cleaned = re.sub(r"[^a-z0-9\-_]+", "-", cleaned)
    cleaned = re.sub(r"-+", "-", cleaned).strip("-")
    return cleaned


def parse_tags_input(raw_tags: Any, custom_tags: Optional[str] = None) -> List[str]:
    """Parse multi-select list and optional comma-separated custom tags."""
    tags: Set[str] = set()

    if isinstance(raw_tags, str):
        candidates = [raw_tags]
    elif isinstance(raw_tags, (list, tuple, set)):
        candidates = list(raw_tags)
    else:
        candidates = []

    for item in candidates:
        normalized = normalize_tag(str(item))
        if normalized:
            tags.add(normalized)

    if custom_tags:
        for part in custom_tags.split(","):
            normalized = normalize_tag(part)
            if normalized:
                tags.add(normalized)

    return sorted(tags)


def infer_tags_from_text(text: str, extra_texts: Optional[List[str]] = None) -> List[str]:
    """Infer tags from case folder name, parent category, or description."""
    if not text and not extra_texts:
        return []

    combined = " ".join([text or ""] + (extra_texts or [])).lower()
    tokens = re.split(r"[_\-\s\.]+", combined)
    tags: Set[str] = set()

    for token in tokens:
        if not token:
            continue
        if token in _TAG_INFERENCE:
            tags.add(_TAG_INFERENCE[token])
            continue
        for key, tag in _TAG_INFERENCE.items():
            if key in token:
                tags.add(tag)

    return sorted(tags)


def infer_incident_type_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    lowered = text.lower()
    for key, incident in _INCIDENT_INFERENCE.items():
        if key in lowered:
            return incident
    return None


def load_case_metadata(case_path: str) -> Dict[str, Any]:
    meta_file = os.path.join(case_path, "case_metadata.json")
    if not os.path.exists(meta_file):
        return {}

    try:
        with open(meta_file, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data.get("case_metadata", data)
    except Exception as exc:
        logger.warning("Could not read metadata for %s: %s", case_path, exc)
        return {}


def extract_case_fields(case_path: str, case_name: str) -> Dict[str, Any]:
    """Return incident_type and tags from metadata, with name-based inference fallback."""
    metadata = load_case_metadata(case_path)
    case_info = metadata.get("case_info", {}) if isinstance(metadata, dict) else {}

    incident_type = (case_info.get("incident_type") or "").strip()
    tags = case_info.get("tags") or []
    if isinstance(tags, str):
        tags = parse_tags_input(tags)

    if not tags:
        tags = infer_tags_from_text(case_name, [case_info.get("description", "")])

    if not incident_type or incident_type.lower() == "unknown":
        inferred = infer_incident_type_from_text(case_name)
        incident_type = inferred or incident_type or "Unknown"

    return {
        "incident_type": incident_type,
        "tags": sorted(set(normalize_tag(t) for t in tags if normalize_tag(t))),
    }


def enrich_case_record(case: Dict[str, Any]) -> Dict[str, Any]:
    """Add incident_type and tags to a discover_cases() record."""
    case_path = case.get("path") or ""
    case_name = case.get("name") or ""
    fields = extract_case_fields(case_path, case_name)
    case["incident_type"] = fields["incident_type"]
    case["tags"] = fields["tags"]
    return case


def collect_filter_options(cases: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    incident_types: Set[str] = set()
    tags: Set[str] = set()
    for case in cases:
        incident = (case.get("incident_type") or "").strip()
        if incident and incident.lower() != "unknown":
            incident_types.add(incident)
        for tag in case.get("tags") or []:
            if tag:
                tags.add(tag)
    return {
        "incident_types": sorted(incident_types),
        "case_tags": sorted(tags),
    }
