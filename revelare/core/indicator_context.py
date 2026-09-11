"""
Shared indicator compile flags, crypto checks, and name-line disambiguation.

CLI and GUI extractors both import this module. Policy:

- Strong crypto (bc1 / 0x+40 hex / Base58Check) is kept with no nearby keywords.
- Matches inside URLs, emails, or path/query tokens are always dropped.
- Ambiguous 1/3 Base58 that fails checksum is kept only if crypto words are nearby.
- Person names: keep isolated First Last (Jane Doe / Martin Brown), optional
  middle initial (Mary A. Smith), optional Jr/Sr/III. No legal-keyword gate.
  Drop email headers, salutations, title-case document runs, and spreadsheet
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
    "hi tyra",
    "probable cause",
    "coming soon",
    "cover reveal",
    "child loss",
    "lulu publishing",
    "ingram sparks",
    "sinch voice",
    "goodreads author",
    "social me",
    "author you",
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
    "cycle",
    "reason",
    "description",
    "details",
    "methods",
    "campaign",
    "package",
    "reminders",
    "research",
    "recovery",
    "wellness",
    "goals",
    "keyword",
    "topics",
    "questions",
    "messages",
    "graphics",
    "publishing",
})

_ROLE_PREFIXES = frozenset({
    "inv",
    "det",
    "sgt",
    "tpr",
    "ptl",
    "ofc",
    "cpl",
    "lt",
    "capt",
    "maj",
    "col",
    "hon",
    "atty",
    "esq",
    "dr",
    "mr",
    "mrs",
    "ms",
    "miss",
    "prof",
    "po",
})

_GREETING_FIRST = frozenset({
    "hi",
    "hello",
    "hey",
    "dear",
    "greetings",
})


def _with_simple_plurals(words: Iterable[str]) -> frozenset:
    out = set()
    for word in words:
        token = (word or "").strip().lower()
        if not token:
            continue
        out.add(token)
        if token.endswith("s"):
            out.add(token[:-1])
        else:
            out.add(token + "s")
        if token.endswith("y") and len(token) > 2 and token[-2] not in "aeiou":
            out.add(token[:-1] + "ies")
    return frozenset(out)


# Modest header/form/marketing words. Not a general English deny-list.
_LABEL_WORDS = _with_simple_plurals(_LABEL_TAIL | frozenset({
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
    "view",
    "village",
    "with",
    "your",
    "zone",
    "access",
    "advance",
    "affiant",
    "approach",
    "area",
    "artificial",
    "ave",
    "azimuth",
    "biographical",
    "blvd",
    "browsing",
    "bytes",
    "city",
    "communication",
    "completed",
    "completion",
    "content",
    "dialed",
    "direction",
    "download",
    "dump",
    "duration",
    "editorial",
    "estates",
    "etiquette",
    "history",
    "hwy",
    "hybrid",
    "identifier",
    "information",
    "intelligence",
    "knowledge",
    "latitude",
    "ln",
    "logs",
    "longitude",
    "meadows",
    "mountain",
    "provided",
    "rd",
    "requested",
    "roaming",
    "sessions",
    "serving",
    "successfully",
    "summary",
    "tech",
    "timing",
    "trace",
    "upload",
    "zip",
    "book",
    "copy",
    "plan",
    "account",
    "alternative",
    "author",
    "campaign",
    "cause",
    "chaining",
    "coming",
    "countdown",
    "cover",
    "creative",
    "cycle",
    "description",
    "disconnect",
    "discussion",
    "emotional",
    "goal",
    "goodreads",
    "graphic",
    "grief",
    "hashtag",
    "inspirational",
    "keyword",
    "launch",
    "linked",
    "loss",
    "marketing",
    "me",
    "message",
    "method",
    "our",
    "package",
    "ported",
    "pre",
    "prelaunch",
    "preorder",
    "probable",
    "publishing",
    "question",
    "rate",
    "reader",
    "reason",
    "recovery",
    "reminder",
    "research",
    "reveal",
    "scene",
    "sinch",
    "social",
    "soon",
    "topic",
    "trauma",
    "triangle",
    "voice",
    "wellness",
    "you",
}))

# Ordinary English / document words. If EVERY name token is in this set,
# the hit is a title-case heading, not a person. Surnames like Smith/Brown
# stay out so Jane Doe / Martin Brown / John Smith still match.
_COMMON_ENGLISH = _LABEL_WORDS | _with_simple_plurals({
    "about",
    "after",
    "against",
    "all",
    "also",
    "any",
    "available",
    "based",
    "before",
    "below",
    "between",
    "bill",
    "both",
    "child",
    "click",
    "customer",
    "daisy",
    "each",
    "full",
    "good",
    "head",
    "here",
    "ingram",
    "into",
    "link",
    "lulu",
    "more",
    "next",
    "only",
    "order",
    "other",
    "over",
    "please",
    "same",
    "sparks",
    "thank",
    "thanks",
    "then",
    "true",
    "under",
    "until",
    "updated",
    "using",
    "welcome",
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
    "billing address",
    "probable cause",
    "coming soon",
    "cover reveal",
    "linked accounts",
    "pre-launch package",
    "pre-order reminders",
    "keyword research",
    "grief recovery",
    "child loss",
    "lulu publishing",
    "ingram sparks",
    "sinch voice",
    "goodreads author",
})

_INITIAL_TOKEN_RE = re.compile(r"^[A-Za-z]\.?$")
_NAME_SUFFIX_RE = re.compile(r"^(?:Jr|Sr|II|III|IV)\.?$", re.IGNORECASE)
_TITLE_TOKEN_RE = re.compile(r"^[A-Z][a-z]+(?:['-][A-Z][a-z]+)?$")

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HTML_ENTITY_RE = re.compile(r"&[a-zA-Z]{2,8};")

# Isolated First Last (+ optional middle initial / Jr-Sr-III).
# Pattern family: SO 55194224 / 73720293 (First + optional initial + Last)
# and SO 49563538 (one capital per token, optional Jr/Sr/III). Isolation
# of the title-case run follows SO 61966166 so "Call Detail Records" is
# not sliced into a fake two-word name.
_NAME_TOKEN = r"[A-Z][a-z]+(?:['-][A-Z][a-z]+)?"
_MIDDLE_INITIAL = r"[A-Z]\."
_NAME_SUFFIX = r"(?:Jr|Sr|II|III|IV)\.?"
# Do not use \b at the edges: \b fires at hyphens, which would turn
# "Our Pre-Launch Package" into "Our Pre".
_TITLE_NAME_RE = re.compile(
    r"(?<![\w-])("
    r"(?:" + _NAME_TOKEN + r"\s+" + _MIDDLE_INITIAL + r"\s+" + _NAME_TOKEN + r")"
    r"|"
    r"(?:" + _NAME_TOKEN + r"\s+" + _NAME_TOKEN + r"(?!\s+" + _MIDDLE_INITIAL + r"))"
    r")"
    r"(?:\s+" + _NAME_SUFFIX + r")?"
    r"(?![\w-])"
    r"(?!\s+(?:Case|Date|Time|No|Warrant|Records|Detail)\b)"
    r"(?!\s+" + _NAME_TOKEN + r")"
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
        for piece in re.split(r"[-']", raw):
            cleaned = piece.strip(".'-")
            if not cleaned:
                continue
            if _INITIAL_TOKEN_RE.fullmatch(cleaned):
                continue
            if _NAME_SUFFIX_RE.fullmatch(cleaned):
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
    if not tokens:
        return False
    if tokens[0] in _ROLE_PREFIXES or tokens[0] in _GREETING_FIRST:
        return True
    if len(tokens) < 2:
        return False
    # Repeated title-case token is a header leftover (City City), not a person.
    if len(tokens) == 2 and tokens[0] == tokens[1]:
        return True
    # Any header leftover token disqualifies the candidate.
    if any(token in _LABEL_WORDS for token in tokens):
        return True
    last = tokens[-1]
    if last in _LABEL_TAIL:
        return True
    # Two ordinary English words in title case ("Coming Soon", "Ingram Sparks").
    if all(token in _COMMON_ENGLISH for token in tokens):
        return True
    return False


def _neighbor_token(text: str, start: int, end: int, side: str) -> str:
    if side == "left":
        chunk = text[:start].rstrip()
        if not chunk:
            return ""
        return chunk.split()[-1].strip(".,;:\"'()[]")
    chunk = text[end:].lstrip()
    if not chunk:
        return ""
    return chunk.split()[0].strip(".,;:\"'()[]")


def _is_title_case_run_slice(text: str, start: int, end: int) -> bool:
    """True when the match sits inside a longer Title Case header run."""
    right = _neighbor_token(text, start, end, "right")
    if right and not _NAME_SUFFIX_RE.fullmatch(right):
        if _TITLE_TOKEN_RE.fullmatch(right) or _INITIAL_TOKEN_RE.fullmatch(right):
            return True
    left = _neighbor_token(text, start, end, "left")
    if not left:
        return False
    if not (_TITLE_TOKEN_RE.fullmatch(left) or _INITIAL_TOKEN_RE.fullmatch(left)):
        return False
    # First I. Last after a capitalized verb ("Signed Mary A. Smith") is a name.
    # A bare First Last after another Title Case word is a header tail.
    matched = text[start:end]
    if re.search(r"\s[A-Z]\.\s", matched):
        return False
    return True


def is_blocked_name_phrase(name: str) -> bool:
    lowered = (name or "").strip().lower()
    if not lowered:
        return True
    if lowered in _BODY_NAME_PHRASE_BLOCKLIST:
        return True
    if lowered in _KNOWN_HEADER_PHRASES:
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
            if _is_title_case_run_slice(visible, match.start(), match.end()):
                continue
            if is_blocked_name_phrase(candidate):
                continue
            if not DataValidator.is_valid_person_name(candidate):
                continue
            seen.add(candidate)
            found.append(candidate)
    return found
