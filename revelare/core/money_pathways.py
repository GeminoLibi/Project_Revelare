"""
Bank / fintech / gambling pathway detectors (shared CLI + web).

Brand and site names are per-case pathway indicators. They are NOT strong
selectors for Link Analysis. Nearby payment tokens (cashtag, handle, account,
routing, last-4) ARE linkable.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Sequence, Tuple

PATHWAY_CATEGORIES = frozenset({
    "Financial_Institutions",
    "Fintech_Apps",
    "Gambling_Sites",
})

PAYMENT_TOKEN_CATEGORY = "Payment_Tokens"

# Cross-case graph / dashboard strong selectors. Pathway brand names stay out.
LINK_ANALYSIS_CATEGORIES = frozenset({
    "Email_Addresses",
    "Phone_Numbers",
    "Bitcoin_Addresses",
    "Ethereum_Addresses",
    "Monero_Addresses",
    "Credit_Card_Numbers",
    "Credit_Card_VisaMcDiscover",
    "Credit_Card_Amex",
    "MD5_Hashes",
    "Device_IDs_UUIDs",
    "IBAN",
    PAYMENT_TOKEN_CATEGORY,
})

_NEAR_WINDOW = 80
_WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "money_pathways.json",
)

# Cashtag: $name not $50. Handle: @user not user@host.
_CASHTAG_RE = re.compile(r"(?<![A-Za-z0-9])\$[A-Za-z][A-Za-z0-9_]{1,24}(?![A-Za-z0-9_])")
_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9._])@[A-Za-z][A-Za-z0-9._]{1,24}(?![A-Za-z0-9._])")
_EMAIL_LIKE_RE = re.compile(r"^@[A-Za-z0-9._]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_LAST4_RE = re.compile(
    r"(?i)(?:last\s*(?:4|four)|ending\s+in|x{4}|\*{4})\s*[:#\-]?\s*(\d{4})"
)
_ROUTING_LABELED_RE = re.compile(
    r"(?i)routing(?:\s*(?:number|#|num(?:ber)?))?\s*[:#\-]?\s*(\d{9})"
)
_ACCT_LABELED_RE = re.compile(
    r"(?i)(?:acct|account)(?:\s*(?:#|num(?:ber)?))?\s*[:#\-]?\s*(\d[\d\-\s]{5,22}\d)"
)
_DIGIT_RUN_RE = re.compile(r"(?<!\d)(\d[\d\-\s]{6,22}\d)(?!\d)")
_ACCT_HINT_RE = re.compile(r"(?i)\b(?:acct|account|routing)\b")

_compiled_rules: Optional[List[Tuple[re.Pattern, str, str]]] = None
_wordlist_counts: Optional[Dict[str, int]] = None


def clear_money_pathway_cache() -> None:
    global _compiled_rules, _wordlist_counts
    _compiled_rules = None
    _wordlist_counts = None


def wordlist_counts() -> Dict[str, int]:
    load_money_pathway_rules()
    return dict(_wordlist_counts or {})


def _alias_to_pattern(alias: str) -> str:
    escaped = re.escape(alias.strip())
    escaped = re.sub(r"\\ ", r"\\s+", escaped)
    return r"(?<![A-Za-z0-9])" + escaped + r"(?![A-Za-z0-9])"


def _normalize_alias(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def load_money_pathway_rules() -> List[Tuple[re.Pattern, str, str]]:
    """Return (pattern, category, canonical_name) sorted longest-alias first."""
    global _compiled_rules, _wordlist_counts
    if _compiled_rules is not None:
        return _compiled_rules

    with open(_WORDLIST_PATH, "r", encoding="ascii") as handle:
        data = json.load(handle)

    counts: Dict[str, int] = {}
    pending: List[Tuple[int, str, str, str]] = []
    for category in ("Financial_Institutions", "Fintech_Apps", "Gambling_Sites"):
        entries = data.get(category) or []
        counts[category] = len(entries)
        for entry in entries:
            name = (entry.get("name") or "").strip()
            if not name:
                continue
            aliases = [name]
            for alias in entry.get("aliases") or []:
                alias = (alias or "").strip()
                if alias and alias not in aliases:
                    aliases.append(alias)
            for alias in aliases:
                pending.append((len(alias), alias, category, name))

    pending.sort(key=lambda row: (-row[0], row[1].lower()))
    rules: List[Tuple[re.Pattern, str, str]] = []
    for _length, alias, category, canonical in pending:
        pattern = re.compile(_alias_to_pattern(alias), re.IGNORECASE)
        rules.append((pattern, category, canonical))

    _compiled_rules = rules
    _wordlist_counts = counts
    return rules


def _near_window(text: str, start: int, end: int) -> Tuple[str, int]:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    lo = max(line_start, start - _NEAR_WINDOW)
    hi = min(line_end, end + _NEAR_WINDOW)
    return text[lo:hi], lo


def _digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _token_ok_span(abs_start: int, abs_end: int, brand_spans: Sequence[Tuple[int, int]]) -> bool:
    for b_start, b_end in brand_spans:
        if abs_start < b_end and abs_end > b_start:
            return False
    return True


def _extract_nearby_tokens(
    text: str,
    start: int,
    end: int,
    brand_spans: Sequence[Tuple[int, int]],
) -> List[Tuple[str, str]]:
    """Return [(token_value, token_type), ...] near a pathway match."""
    window, origin = _near_window(text, start, end)
    found: List[Tuple[str, str]] = []
    seen = set()

    def add(value: str, token_type: str, abs_start: int, abs_end: int) -> None:
        if not value or value in seen:
            return
        if not _token_ok_span(abs_start, abs_end, brand_spans):
            return
        seen.add(value)
        found.append((value, token_type))

    for match in _CASHTAG_RE.finditer(window):
        add(
            match.group(0).lower(),
            "Cashtag",
            origin + match.start(),
            origin + match.end(),
        )

    for match in _HANDLE_RE.finditer(window):
        raw = match.group(0)
        if "." in raw and _EMAIL_LIKE_RE.match(raw):
            continue
        # Drop user@domain slices that slipped past (handle must not look like email).
        if re.search(r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", raw[1:]):
            continue
        add(
            raw.lower(),
            "Handle",
            origin + match.start(),
            origin + match.end(),
        )

    for match in _LAST4_RE.finditer(window):
        last4 = match.group(1)
        add(
            "****%s" % last4,
            "Last4",
            origin + match.start(1),
            origin + match.end(1),
        )

    for match in _ROUTING_LABELED_RE.finditer(window):
        routing = match.group(1)
        add(
            routing,
            "Routing",
            origin + match.start(1),
            origin + match.end(1),
        )

    for match in _ACCT_LABELED_RE.finditer(window):
        digits = _digits_only(match.group(1))
        if 6 <= len(digits) <= 17:
            add(
                digits,
                "Account",
                origin + match.start(1),
                origin + match.end(1),
            )

    if _ACCT_HINT_RE.search(window):
        for match in _DIGIT_RUN_RE.finditer(window):
            digits = _digits_only(match.group(1))
            if 8 <= len(digits) <= 17:
                add(
                    digits,
                    "Account",
                    origin + match.start(1),
                    origin + match.end(1),
                )
            elif len(digits) == 9:
                add(
                    digits,
                    "Routing",
                    origin + match.start(1),
                    origin + match.end(1),
                )

    return found


def _build_context(
    file_name: str,
    offset: int,
    match_start: int,
    extra: List[str],
    segment_id: Optional[str],
    segment_anchor: Optional[str],
    multi_account_risk: bool,
    provider: Optional[str],
    file_path: Optional[str],
) -> str:
    parts = [
        "File: %s" % file_name,
        "Position: %s" % (offset + match_start),
    ]
    parts.extend(extra)
    if provider:
        parts.append("Provider: %s" % provider)
    if segment_id:
        parts.append("Segment: %s" % segment_id)
    if segment_anchor:
        parts.append("SegmentAnchor: %s" % segment_anchor)
    if multi_account_risk:
        parts.append("MultiAccountRisk: true")
    if file_path:
        from revelare.core.source_ingest import format_source_audit_fields
        parts.extend(format_source_audit_fields(file_path))
    return " | ".join(parts)


def extract_money_pathways(
    text: str,
    file_name: str,
    offset: int = 0,
    segment_id: Optional[str] = None,
    segment_anchor: Optional[str] = None,
    multi_account_risk: bool = False,
    provider: Optional[str] = None,
    file_path: Optional[str] = None,
) -> Dict[str, Dict[str, str]]:
    """Return pathway categories plus nearby Payment_Tokens."""
    findings: Dict[str, Dict[str, str]] = {}
    if not text or not isinstance(text, str):
        return findings

    rules = load_money_pathway_rules()
    occupied: List[Tuple[int, int]] = []
    brand_hits: List[Tuple[int, int, str, str]] = []

    for pattern, category, canonical in rules:
        for match in pattern.finditer(text):
            start, end = match.start(), match.end()
            overlap = False
            for occ_start, occ_end in occupied:
                if start < occ_end and end > occ_start:
                    overlap = True
                    break
            if overlap:
                continue
            occupied.append((start, end))
            brand_hits.append((start, end, category, canonical))
            extra = [
                "Type: Pathway",
                "Pathway: %s" % canonical,
                "PathwayType: %s" % category,
            ]
            context = _build_context(
                file_name,
                offset,
                start,
                extra,
                segment_id,
                segment_anchor,
                multi_account_risk,
                provider,
                file_path,
            )
            findings.setdefault(category, {})[canonical] = context

    brand_spans = [(s, e) for s, e, _c, _n in brand_hits]
    for start, end, category, canonical in brand_hits:
        for token, token_type in _extract_nearby_tokens(text, start, end, brand_spans):
            extra = [
                "Type: %s" % token_type,
                "Pathway: %s" % canonical,
                "PathwayType: %s" % category,
            ]
            context = _build_context(
                file_name,
                offset,
                start,
                extra,
                segment_id,
                segment_anchor,
                multi_account_risk,
                provider,
                file_path,
            )
            findings.setdefault(PAYMENT_TOKEN_CATEGORY, {})[token] = context

    return findings


def is_link_analysis_category(category: str) -> bool:
    return category in LINK_ANALYSIS_CATEGORIES


def link_analysis_sql_filter() -> Tuple[str, List[str]]:
    """SQL fragment and bind params: indicator_type IN (...strong selectors...)."""
    cats = sorted(LINK_ANALYSIS_CATEGORIES)
    placeholders = ", ".join("?" for _ in cats)
    return "indicator_type IN (%s)" % placeholders, cats
