"""
Shared indicator compile flags, crypto checks, and name-line disambiguation.

CLI and GUI extractors both import this module. Policy:

- Strong crypto (bc1 / 0x+40 hex / Base58Check) is kept with no nearby keywords.
- Matches inside URLs, emails, or path/query tokens are always dropped.
- Ambiguous 1/3 Base58 that fails checksum is kept only if crypto words are nearby.
- Person names: keep plausible First Last (Jane Doe / Martin Brown) with no
  legal-keyword gate. Drop email headers, salutations, and spreadsheet/legal
  labels (Case No, Start Date, Emergency Response, and similar).
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from revelare.config.config import Config

CRYPTO_CATEGORIES = frozenset({
    "Bitcoin_Addresses",
    "Ethereum_Addresses",
    "Monero_Addresses",
})

# Crypto charset is case-significant (Base58 / Bech32). Do not IGNORECASE these.
CASE_SENSITIVE_CATEGORIES = CRYPTO_CATEGORIES

_CRYPTO_CONTEXT_RE = re.compile(
    r"\b(?:wallet|btc|bitcoin|eth|ether(?:eum)?|usdt|usdc|tether|"
    r"crypto(?:currency)?|metamask|coinbase|binance|kraken|blockchain|"
    r"txid|tx\s*id|send(?:\s+to)?|deposit|withdraw|private\s+key|"
    r"seed\s+phrase|xmr|monero|litecoin|ltc|trc20|erc20|"
    r"(?<![A-Za-z])address(?![A-Za-z]))\b",
    re.IGNORECASE,
)

_URL_SPAN_RE = re.compile(
    r"(?:https?|sftp|ftp|ws)://[^\s<>\"'{}|\\^`\[\]]+",
    re.IGNORECASE,
)
_EMAIL_SPAN_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"
)

# One character immediately left of a path/query fragment.
_URI_LEFT = frozenset("/?#=&%")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: idx for idx, ch in enumerate(_B58_ALPHABET)}
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)

_EMAIL_HEADER_RE = re.compile(
    r"(?i)^(?:from|to|cc|bcc|subject|date|sent|reply-to|return-path|"
    r"message-id|received|mime-version|content-type|"
    r"content-transfer-encoding|x-[a-z0-9\-]+)\s*:"
)
_SALUTATION_RE = re.compile(
    r"(?i)^\s*(?:dear|hi|hello|good\s+(?:morning|afternoon|evening))\b"
)
_ALLCAPS_LABEL_RE = re.compile(r"^[A-Z][A-Z \-/]{1,40}:\s*$")

# Tiny phrase list only (not a token deny-list) for leftover title-case junk.
_BODY_NAME_PHRASE_BLOCKLIST = frozenset({
    "click here",
    "dear sir",
    "dear madam",
    "editorial review",
    "meeting link",
    "united states",
    "welcome onboard",
    "true copy",
})

# Last token of a form/spreadsheet header when the leading tokens are labels too.
_LABEL_TAIL = frozenset({
    "no",
    "date",
    "time",
    "records",
    "address",
    "warrant",
    "response",
    "number",
    "status",
    "type",
    "name",
})

# Modest header/form words. Not a general English deny-list.
_LABEL_WORDS = _LABEL_TAIL | frozenset({
    "activation",
    "and",
    "at",
    "begin",
    "billing",
    "business",
    "by",
    "call",
    "called",
    "case",
    "cell",
    "code",
    "contact",
    "coordinated",
    "data",
    "destination",
    "detail",
    "device",
    "document",
    "effective",
    "email",
    "emergency",
    "end",
    "expiration",
    "file",
    "first",
    "for",
    "from",
    "gmt",
    "in",
    "item",
    "last",
    "legal",
    "local",
    "location",
    "messaging",
    "middle",
    "network",
    "of",
    "offset",
    "on",
    "page",
    "partner",
    "phone",
    "physical",
    "record",
    "report",
    "return",
    "search",
    "section",
    "service",
    "site",
    "start",
    "subject",
    "subscriber",
    "switch",
    "termination",
    "the",
    "this",
    "to",
    "tower",
    "universal",
    "utc",
    "with",
    "zone",
})

_KNOWN_HEADER_PHRASES = frozenset({
    "call detail records",
    "case no",
    "coordinated universal time",
    "emergency response",
    "end date",
    "search warrant",
    "start date",
    "start date end",
    "tower address",
})

_INITIAL_TOKEN_RE = re.compile(r"^[A-Za-z]\.?$")

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ENTITY_RE = re.compile(r"&[a-zA-Z]{2,8};")

_TITLE_NAME_RE = re.compile(
    r"\b("
    r"[A-Z][a-z]+(?:['-][A-Z][a-z]+)?"
    r"(?:\s+[A-Z]\.)?"
    r"(?:\s+[A-Z][a-z]+(?:['-][A-Z][a-z]+)?){1,2}"
    r")\b"
)

_compiled_patterns: Optional[Dict[str, re.Pattern]] = None


def clear_pattern_cache() -> None:
    global _compiled_patterns
    _compiled_patterns = None


def compiled_regex_patterns() -> Dict[str, re.Pattern]:
    """Compile Config.REGEX_PATTERNS once. Crypto stays case-sensitive."""
    global _compiled_patterns
    if _compiled_patterns is None:
        compiled: Dict[str, re.Pattern] = {}
        for category, pattern in Config.REGEX_PATTERNS.items():
            flags = re.MULTILINE
            if category not in CASE_SENSITIVE_CATEGORIES:
                flags |= re.IGNORECASE
            compiled[category] = re.compile(pattern, flags)
        _compiled_patterns = compiled
    return _compiled_patterns


def iter_url_spans(text: str) -> List[Tuple[int, int]]:
    return [(m.start(), m.end()) for m in _URL_SPAN_RE.finditer(text or "")]


def iter_email_spans(text: str) -> List[Tuple[int, int]]:
    return [(m.start(), m.end()) for m in _EMAIL_SPAN_RE.finditer(text or "")]


def _overlaps(start: int, end: int, spans: Sequence[Tuple[int, int]]) -> bool:
    for span_start, span_end in spans:
        if start < span_end and end > span_start:
            return True
    return False


def is_path_or_query_fragment(text: str, start: int, end: int) -> bool:
    """True when the match sits inside a URL path, query, or similar token."""
    if start > 0 and text[start - 1] in _URI_LEFT:
        return True
    if end < len(text) and text[end] in "/?#&=%":
        return True
    # Longer alphanumeric token: /1Boat...xyz extra chars after a regex-sized slice.
    if end < len(text) and (text[end].isalnum() or text[end] in "_-"):
        return True
    if start > 0 and (text[start - 1].isalnum() or text[start - 1] in "_-"):
        return True
    return False


def has_crypto_context(text: str, start: int, end: int, window: int = 80) -> bool:
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return bool(_CRYPTO_CONTEXT_RE.search(text[lo:hi]))


def _b58decode(value: str) -> Optional[bytes]:
    try:
        num = 0
        for char in value:
            num = num * 58 + _B58_INDEX[char]
    except KeyError:
        return None
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading) + full


def is_base58check(value: str) -> bool:
    decoded = _b58decode(value)
    if not decoded or len(decoded) < 5:
        return False
    payload, checksum = decoded[:-4], decoded[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return digest == checksum


def _bech32_polymod(values: Iterable[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _BECH32_GEN[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp]


def is_bech32_address(value: str) -> bool:
    if not value:
        return False
    if value != value.lower() and value != value.upper():
        return False
    lowered = value.lower()
    if not lowered.startswith("bc1") or len(lowered) < 14:
        return False
    pos = lowered.rfind("1")
    if pos < 1:
        return False
    hrp, data_part = lowered[:pos], lowered[pos + 1:]
    if hrp != "bc" or len(data_part) < 6:
        return False
    try:
        data = [_BECH32_CHARSET.index(ch) for ch in data_part]
    except ValueError:
        return False
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    # Bech32 witness v0 (bc1q) uses const 1; Bech32m taproot (bc1p) uses 0x2bc830a3.
    if lowered[2:4] == "1p":
        return polymod == 0x2BC830A3
    return polymod == 1


def is_strong_bitcoin(value: str) -> bool:
    if value.startswith(("bc1", "BC1")):
        return is_bech32_address(value)
    if value[:1] in ("1", "3") and 26 <= len(value) <= 35:
        return is_base58check(value)
    return False


def is_strong_ethereum(value: str) -> bool:
    if len(value) != 42:
        return False
    if not (value.startswith("0x") or value.startswith("0X")):
        return False
    try:
        int(value[2:], 16)
    except ValueError:
        return False
    return True


def is_strong_monero(value: str) -> bool:
    if len(value) != 95:
        return False
    if value[0] != "4" or value[1] not in "0123456789AB":
        return False
    return all(ch in _B58_ALPHABET for ch in value)


def is_strong_crypto(category: str, value: str) -> bool:
    if category == "Bitcoin_Addresses":
        return is_strong_bitcoin(value)
    if category == "Ethereum_Addresses":
        return is_strong_ethereum(value)
    if category == "Monero_Addresses":
        return is_strong_monero(value)
    return False


def accept_crypto_match(
    category: str,
    value: str,
    text: str,
    start: int,
    end: int,
    url_spans: Optional[Sequence[Tuple[int, int]]] = None,
    email_spans: Optional[Sequence[Tuple[int, int]]] = None,
) -> bool:
    """
    Keep strong standalone addresses. Drop URL/email/path embeddings.
    Ambiguous Base58 needs nearby crypto wording.
    """
    if not value or category not in CRYPTO_CATEGORIES:
        return False
    if url_spans is None:
        url_spans = iter_url_spans(text)
    if email_spans is None:
        email_spans = iter_email_spans(text)
    if _overlaps(start, end, url_spans) or _overlaps(start, end, email_spans):
        return False
    if is_path_or_query_fragment(text, start, end):
        return False
    if is_strong_crypto(category, value):
        return True
    # Ambiguous leftover (looks like 1/3 Base58, no checksum): context may save it.
    if category == "Bitcoin_Addresses" and value[:1] in ("1", "3"):
        return has_crypto_context(text, start, end)
    return False


def is_email_header_line(line: str) -> bool:
    return bool(_EMAIL_HEADER_RE.match(line or ""))


def is_salutation_line(line: str) -> bool:
    return bool(_SALUTATION_RE.match(line or ""))


def is_allcaps_form_label(line: str) -> bool:
    return bool(_ALLCAPS_LABEL_RE.match((line or "").strip()))


def should_skip_name_line(line: str) -> bool:
    """Drop From:/Subject:/Dear/ALL-CAPS labels. Do not require legal keywords."""
    if not line or not line.strip():
        return True
    if is_email_header_line(line):
        return True
    if is_salutation_line(line):
        return True
    if is_allcaps_form_label(line):
        return True
    return False


def _name_tokens(name: str) -> List[str]:
    tokens: List[str] = []
    for raw in re.split(r"\s+", (name or "").strip()):
        cleaned = raw.strip(".'-")
        if not cleaned:
            continue
        if _INITIAL_TOKEN_RE.fullmatch(cleaned):
            continue
        tokens.append(cleaned.lower())
    return tokens


def is_form_label_name(name: str) -> bool:
    """True for spreadsheet/legal headers, not person names."""
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    if lowered in _KNOWN_HEADER_PHRASES:
        return True
    tokens = _name_tokens(name)
    if len(tokens) < 2:
        return False
    # Every token is a form/header word (covers 2-word labels and 3+ form phrases).
    if all(token in _LABEL_WORDS for token in tokens):
        return True
    last = tokens[-1]
    heads = tokens[:-1]
    if last in _LABEL_TAIL and heads and all(token in _LABEL_WORDS for token in heads):
        return True
    return False


def is_blocked_name_phrase(name: str) -> bool:
    lowered = (name or "").strip().lower()
    if not lowered:
        return True
    if lowered in _BODY_NAME_PHRASE_BLOCKLIST:
        return True
    return is_form_label_name(name)


def iter_body_person_names(text: str) -> List[str]:
    """Title-case First Last in non-header lines. No keyword gate."""
    from revelare.core.validators import DataValidator

    found: List[str] = []
    seen = set()
    if not text:
        return found
    for line in text.splitlines():
        if should_skip_name_line(line):
            continue
        visible = _HTML_ENTITY_RE.sub(" ", _HTML_TAG_RE.sub(" ", line))
        visible = re.sub(r"\s+", " ", visible).strip()
        if not visible or should_skip_name_line(visible):
            continue
        for match in _TITLE_NAME_RE.finditer(visible):
            candidate = re.sub(r"\s+", " ", match.group(1).strip())
            if candidate in seen:
                continue
            if is_blocked_name_phrase(candidate):
                continue
            if not DataValidator.is_valid_person_name(candidate):
                continue
            seen.add(candidate)
            found.append(candidate)
    return found
