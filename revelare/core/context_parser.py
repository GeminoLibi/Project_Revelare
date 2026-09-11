"""Parse indicator context strings produced during extraction."""
from typing import Any, Dict, Optional


def parse_context_fields(context: Optional[str]) -> Dict[str, str]:
    if not context:
        return {}
    fields: Dict[str, str] = {}
    for part in str(context).split("|"):
        part = part.strip()
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        normalized = key.strip().lower().replace(" ", "_")
        fields[normalized] = value.strip()
    return fields


def contexts_share_segment(context_a: Optional[str], context_b: Optional[str]) -> bool:
    """True when two indicators can be linked (same file segment or no segmentation)."""
    fields_a = parse_context_fields(context_a)
    fields_b = parse_context_fields(context_b)

    file_a = fields_a.get("file")
    file_b = fields_b.get("file")
    if file_a and file_b and file_a != file_b:
        return False

    seg_a = fields_a.get("segment")
    seg_b = fields_b.get("segment")
    if seg_a and seg_b and seg_a != seg_b:
        return False

    return True


def get_segment_key(context: Optional[str]) -> Optional[str]:
    fields = parse_context_fields(context)
    file_name = fields.get("file")
    segment = fields.get("segment")
    if not file_name:
        return None
    if segment:
        return f"{file_name}::{segment}"
    return file_name
