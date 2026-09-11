"""
Extract person names only when tied to a subject role (account holder, warrant
target, victim, etc.). Generic title-case names in body text are ignored.
"""
import re
from typing import Dict, List, Optional, Tuple

from revelare.core.validators import DataValidator

# (compiled_pattern, role, source_label)
_SUBJECT_NAME_RULES: List[Tuple[re.Pattern, str, str]] = []

_RAW_RULES = [
    # Google / carrier subscriber returns
    (r"(?im)^(?:Account\s+Holder(?:\s+Name)?|Subscriber\s+Name|Customer\s+Name|Registered\s+Name|Full\s+Name)\s*[:=]\s*(.+)$", "account_holder", "provider_return"),
    (r"(?im)^(?:Given\s+Name|First\s+Name)\s*[:=]\s*(.+)$", "account_holder", "provider_return"),
    (r"(?im)^(?:Family\s+Name|Last\s+Name|Surname)\s*[:=]\s*(.+)$", "account_holder", "provider_return"),
    (r"(?im)^(?:Authorized\s+User(?:\s+Name)?|Additional\s+User)\s*[:=]\s*(.+)$", "account_holder", "provider_return"),
    # Warrant / legal targeting language
    (r"(?im)^(?:Subject|Target(?:\s+Name)?|Suspect(?:\s+Name)?)\s*[:=]\s*(.+)$", "warrant_subject", "warrant"),
    # Victims / complainants
    (r"(?im)^(?:Victim(?:\s+Name)?|Complainant|Reporting\s+Party|Customer(?:\s+Name)?)\s*[:=]\s*(.+)$", "victim", "victim_record"),
    # Email display names with angle-bracket address
    (r"(?im)^(?:From|To|Cc|Bcc)\s*:\s*\"?([A-Za-z][A-Za-z\s\.\'-]{2,60})\"?\s*<[^>\s]+@[^>\s]+>", "email_party", "email_header"),
    (r"(?im)^(?:From|To|Cc|Bcc)\s*:\s*([A-Za-z][A-Za-z\s\.\'-]{2,60})\s+<[^>\s]+@[^>\s]+>", "email_party", "email_header"),
]

_EXCLUDE_LINE_PATTERNS = [
    re.compile(r"(?i)\binvestigator\b"),
    re.compile(r"(?i)\b(?:presiding\s+)?judge\b"),
    re.compile(r"(?i)\b(?:special\s+)?agent\b"),
    re.compile(r"(?i)\bdetective\b"),
    re.compile(r"(?i)\battorney\b"),
    re.compile(r"(?i)\btextnow,\s*inc\b"),
    re.compile(r"(?i)\blegal\s+department\b"),
]

for raw_pattern, role, source in _RAW_RULES:
    _SUBJECT_NAME_RULES.append((re.compile(raw_pattern), role, source))


def _clean_candidate(raw: str) -> Optional[str]:
    if not raw:
        return None
    candidate = raw.strip().strip('"\'.,;')
    candidate = re.sub(r"\s+", " ", candidate)
    if len(candidate) < 5:
        return None
    for pattern in _EXCLUDE_LINE_PATTERNS:
        if pattern.search(candidate):
            return None
    if not DataValidator.is_valid_person_name(candidate):
        return None
    return candidate


def _build_context(
    file_name: str,
    role: str,
    source: str,
    field: str,
    segment_id: Optional[str] = None,
    segment_anchor: Optional[str] = None,
    multi_account_risk: bool = False,
) -> str:
    parts = [
        f"File: {file_name}",
        f"Role: {role}",
        f"Source: {source}",
        f"Field: {field}",
        "Type: Subject Name",
    ]
    if segment_id:
        parts.append(f"Segment: {segment_id}")
    if segment_anchor:
        parts.append(f"SegmentAnchor: {segment_anchor}")
    if multi_account_risk:
        parts.append("MultiAccountRisk: true")
    return " | ".join(parts)


def extract_subject_names(
    text: str,
    file_name: str,
    segment_id: Optional[str] = None,
    segment_anchor: Optional[str] = None,
    multi_account_risk: bool = False,
) -> Dict[str, str]:
    """Return {name: context} for Subject_Names category."""
    results: Dict[str, str] = {}
    if not text:
        return results

    for pattern, role, source in _SUBJECT_NAME_RULES:
        for match in pattern.finditer(text):
            candidate = _clean_candidate(match.group(1))
            if not candidate:
                continue
            context = _build_context(
                file_name=file_name,
                role=role,
                source=source,
                field=pattern.pattern[:40],
                segment_id=segment_id,
                segment_anchor=segment_anchor,
                multi_account_risk=multi_account_risk,
            )
            results[candidate] = context

    # Combine Google-style Given + Family on adjacent lines
    given = re.findall(r"(?im)^Given\s+Name\s*[:=]\s*(.+)$", text)
    family = re.findall(r"(?im)^Family\s+Name\s*[:=]\s*(.+)$", text)
    if given and family:
        combined = _clean_candidate(f"{given[0].strip()} {family[0].strip()}")
        if combined:
            context = _build_context(
                file_name=file_name,
                role="account_holder",
                source="google_return",
                field="Given Name + Family Name",
                segment_id=segment_id,
                segment_anchor=segment_anchor,
                multi_account_risk=multi_account_risk,
            )
            results[combined] = context

    return results
