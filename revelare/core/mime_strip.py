"""
Mask encoded image/binary MIME bodies before IOC regex.

Email processors treat .eml/.mbox as text, so base64 image parts get sliced into
wallet-shaped tokens. This module finds those parts and replaces the bodies with
spaces (newlines kept) so crypto, names, and other IOCs are not scanned there.

Text/plain and text/html parts are left intact. Standalone wallets in those
parts still match without nearby keywords.
"""
from __future__ import annotations

import re
from typing import Iterator, List, Tuple

_QUICK_HINT_RE = re.compile(
    r"(?i)content-type:|content-transfer-encoding:|data:image/"
)
_BOUNDARY_DECL_RE = re.compile(
    r'(?i)boundary\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^\s;]+))'
)
_IMAGE_TYPE_RE = re.compile(r"(?i)content-type:\s*(?:image|audio|video)/")
_OCTET_TYPE_RE = re.compile(r"(?i)content-type:\s*application/octet-stream")
_OFFICE_TYPE_RE = re.compile(
    r"(?i)content-type:\s*application/(?:pdf|zip|x-zip-compressed|msword|vnd\.)"
)
_IMAGE_NAME_RE = re.compile(
    r"(?i)(?:file)?name\*?(?:\s*=\s*(?:UTF-8''))?[\s\"']*[^\"';\r\n]*"
    r"\.(?:jpe?g|png|gif|webp|bmp|tiff?|svg|ico|heic|heif)\b"
)
_BASE64_CTE_RE = re.compile(r"(?i)content-transfer-encoding:\s*base64")
_CONTENT_ID_RE = re.compile(r"(?i)content-id\s*:")
_DISPOSITION_RE = re.compile(r"(?i)content-disposition\s*:")
_DATA_URI_RE = re.compile(
    r"data:image/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=\s]+",
    re.IGNORECASE,
)
_BLANK_LINE_RE = re.compile(r"\r?\n\r?\n")


def _boundary_token(match: re.Match) -> str:
    return (match.group(1) or match.group(2) or match.group(3) or "").strip()


def _declared_boundaries(text: str) -> List[str]:
    seen = []
    found = set()
    for match in _BOUNDARY_DECL_RE.finditer(text):
        token = _boundary_token(match)
        if token and token not in found:
            found.add(token)
            seen.append(token)
    return seen


def _part_is_encoded_media(header_block: str) -> bool:
    """True for image/audio/video parts and clearly-binary image attachments."""
    if not header_block:
        return False
    if _IMAGE_TYPE_RE.search(header_block):
        return True
    image_name = bool(_IMAGE_NAME_RE.search(header_block))
    cte_base64 = bool(_BASE64_CTE_RE.search(header_block))
    has_cid = bool(_CONTENT_ID_RE.search(header_block))
    octet = bool(_OCTET_TYPE_RE.search(header_block))
    office = bool(_OFFICE_TYPE_RE.search(header_block))
    disposition = bool(_DISPOSITION_RE.search(header_block))

    if image_name and (cte_base64 or has_cid or octet or disposition):
        return True
    # cid: inline parts often arrive as octet-stream + base64 with a Content-ID.
    if has_cid and cte_base64 and (octet or image_name):
        return True
    if octet and cte_base64 and image_name:
        return True
    if office and cte_base64:
        return True
    return False


def _iter_boundary_markers(text: str, boundaries: List[str]) -> List[Tuple[int, int, bool]]:
    """Return (start, end, is_closing) for --boundary and --boundary-- lines."""
    if not boundaries:
        return []
    alt = "|".join(re.escape(item) for item in boundaries)
    marker_re = re.compile(r"(?m)^--" + "(?:" + alt + ")" + r"(--)?[ \t]*\r?\n")
    markers = []
    for match in marker_re.finditer(text):
        markers.append((match.start(), match.end(), bool(match.group(1))))
    return markers


def iter_encoded_binary_spans(text: str) -> Iterator[Tuple[int, int]]:
    """Yield [start, end) spans of encoded image/binary payloads in raw MIME."""
    if not text:
        return

    boundaries = _declared_boundaries(text)
    markers = _iter_boundary_markers(text, boundaries)

    if markers:
        for idx, (marker_start, marker_end, is_close) in enumerate(markers):
            if is_close:
                continue
            part_start = marker_end
            part_end = markers[idx + 1][0] if idx + 1 < len(markers) else len(text)
            blank = _BLANK_LINE_RE.search(text, part_start, part_end)
            if not blank:
                continue
            header = text[part_start:blank.start()]
            if _part_is_encoded_media(header):
                yield blank.end(), part_end
    else:
        blank = _BLANK_LINE_RE.search(text)
        if blank:
            header = text[:blank.start()]
            if _part_is_encoded_media(header) or (
                _IMAGE_TYPE_RE.search(header) and _BASE64_CTE_RE.search(header)
            ):
                yield blank.end(), len(text)

    for match in _DATA_URI_RE.finditer(text):
        yield match.start(), match.end()


def mask_encoded_binary_regions(text: str) -> str:
    """
    Replace encoded image/binary bodies with spaces. Newlines are kept so the
    rest of the message stays line-oriented. No-op when MIME hints are absent.
    """
    if not text or not _QUICK_HINT_RE.search(text):
        return text

    spans = list(iter_encoded_binary_spans(text))
    if not spans:
        return text

    chars = list(text)
    n = len(chars)
    for start, end in spans:
        lo = max(0, start)
        hi = min(n, end)
        for i in range(lo, hi):
            if chars[i] not in "\r\n":
                chars[i] = " "
    return "".join(chars)
