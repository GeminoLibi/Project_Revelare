"""
Detect provider returns with multiple rotating accounts (e.g. TextNow) and
split text into segments so identifiers are not cross-linked across accounts.
"""
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

PHONE_PATTERN = re.compile(
    r"\b(?:\+?1[-.\s]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b"
)
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

BLOCK_SPLIT = re.compile(
    r"\n(?:={6,}|-{6,}|_{6,})\n",
    re.MULTILINE,
)

SECTION_START = re.compile(
    r"(?im)^(?:Subscriber(?:\s+Information|\s+Records)?|Account\s+Information|"
    r"Account\s+ID|User\s+ID|Line\s+ID|MSISDN|Phone\s+Number|Customer\s+ID)\s*[:#]",
)

CSV_HEADER_HINT = re.compile(
    r"(?i)(?:phone|msisdn|subscriber|account.?id|email|user.?id)"
)


@dataclass
class TextSegment:
    segment_id: str
    text: str
    anchor_phone: Optional[str] = None
    anchor_email: Optional[str] = None
    provider: Optional[str] = None


def detect_provider(file_name: str, text: str) -> Optional[str]:
    combined = f"{file_name}\n{text[:5000]}".lower()
    if "textnow" in combined:
        return "TextNow"
    if "google" in combined and any(
        token in combined
        for token in ("google account", "given name", "gaia", "gmail")
    ):
        return "Google"
    if "twilio" in combined:
        return "Twilio"
    return None


def _first_phone(text: str) -> Optional[str]:
    match = PHONE_PATTERN.search(text)
    if not match:
        return None
    return re.sub(r"\D", "", match.group(0))[-10:]


def _first_email(text: str) -> Optional[str]:
    match = EMAIL_PATTERN.search(text)
    return match.group(0).lower() if match else None


def _split_csv_blocks(text: str) -> List[str]:
    lines = text.splitlines()
    blocks: List[List[str]] = []
    current: List[str] = []
    header: Optional[str] = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current:
                blocks.append(current)
                current = []
            continue
        lower = stripped.lower()
        if CSV_HEADER_HINT.search(lower) and "," in stripped:
            if header and stripped == header and current:
                blocks.append(current)
                current = [line]
                continue
            if header is None:
                header = stripped
        current.append(line)

    if current:
        blocks.append(current)

    if len(blocks) <= 1:
        return []
    return ["\n".join(block) for block in blocks if block]


def segment_provider_text(file_name: str, text: str) -> Tuple[List[TextSegment], bool]:
    """
    Return segments and whether multi-account contamination risk is likely.
    """
    provider = detect_provider(file_name, text)
    if not text.strip():
        return [TextSegment(segment_id="seg_001", text=text, provider=provider)], False

    raw_blocks: List[str] = []

    csv_blocks = _split_csv_blocks(text)
    if len(csv_blocks) > 1:
        raw_blocks = csv_blocks
    else:
        parts = BLOCK_SPLIT.split(text)
        if len(parts) > 1:
            raw_blocks = [part.strip() for part in parts if part.strip()]
            raw_blocks = [re.sub(r'^=+\s*', '', block) for block in raw_blocks]
        else:
            matches = list(SECTION_START.finditer(text))
            if len(matches) > 1:
                indices = [match.start() for match in matches]
                indices.append(len(text))
                for index in range(len(indices) - 1):
                    chunk = text[indices[index]: indices[index + 1]].strip()
                    if chunk:
                        raw_blocks.append(chunk)

    if len(raw_blocks) <= 1:
        anchor_phone = _first_phone(text)
        anchor_email = _first_email(text)
        return [
            TextSegment(
                segment_id="seg_001",
                text=text,
                anchor_phone=anchor_phone,
                anchor_email=anchor_email,
                provider=provider,
            )
        ], False

    segments: List[TextSegment] = []
    anchors: List[str] = []
    for index, block in enumerate(raw_blocks, start=1):
        phone = _first_phone(block)
        email = _first_email(block)
        anchor = phone or email or f"block_{index}"
        anchors.append(anchor)
        segments.append(
            TextSegment(
                segment_id=f"seg_{index:03d}",
                text=block,
                anchor_phone=phone,
                anchor_email=email,
                provider=provider,
            )
        )

    unique_anchors = len(set(anchors))
    multi_risk = unique_anchors > 1 and provider in ("TextNow", "Twilio")
    return segments, multi_risk
