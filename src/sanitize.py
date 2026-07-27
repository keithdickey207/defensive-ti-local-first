"""
Sanitization Buffer
-------------------
Neutralizes active links, strips executable payloads / event handlers,
removes control characters, and normalizes text for safe local analysis.
Never executes anything it receives.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

# Active URL schemes → placeholder (keep host-ish token for analyst context)
_URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp|file|javascript|data|vbscript):[^\s<>\"']+",
)
_SCRIPT_RE = re.compile(
    r"(?is)<\s*script[^>]*>.*?<\s*/\s*script\s*>|<\s*/?\s*script[^>]*>",
)
_EVENT_HANDLER_RE = re.compile(
    r"""(?i)\bon\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)""",
)
_HTML_TAG_RE = re.compile(r"(?is)<[^>]+>")
_NULL_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Extremely long base64-looking blobs (often payloads)
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_LONG_TOKEN_RE = re.compile(r"\S{500,}")

MAX_LINE_LEN = 16_384


def sanitize_text(raw: str, *, max_len: int = MAX_LINE_LEN) -> str:
    """Return a safe, normalized string suitable for offline analysis."""
    if raw is None:
        return ""

    text = str(raw)

    # Unicode normalize (reduces homoglyph / mixed-script tricks)
    text = unicodedata.normalize("NFKC", text)

    # Strip nulls and most control chars (keep \t \n \r)
    text = _NULL_CTRL_RE.sub("", text)

    # Neutralize URLs before any further parsing
    text = _URL_RE.sub("[NEUTRALIZED_URL]", text)

    # Strip scripts, event handlers, residual tags
    text = _SCRIPT_RE.sub("[STRIPPED_SCRIPT]", text)
    text = _EVENT_HANDLER_RE.sub("", text)
    text = _HTML_TAG_RE.sub(" ", text)

    # Collapse huge encoded payloads
    text = _LONG_B64_RE.sub("[TRUNCATED_PAYLOAD]", text)
    text = _LONG_TOKEN_RE.sub(lambda m: m.group(0)[:120] + "…[TRUNCATED]", text)

    # Whitespace normalize
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()

    if len(text) > max_len:
        text = text[:max_len] + "…[LINE_TRUNCATED]"

    return text


def sanitize_lines(raw: str) -> list[str]:
    """Split and sanitize each non-empty line."""
    if not raw:
        return []
    out: list[str] = []
    for line in str(raw).splitlines():
        cleaned = sanitize_text(line)
        if cleaned:
            out.append(cleaned)
    return out


def is_probably_safe(text: Optional[str]) -> bool:
    """Quick heuristic: reject empty / pure-control input."""
    if not text:
        return False
    cleaned = sanitize_text(text)
    return bool(cleaned and cleaned.strip())
