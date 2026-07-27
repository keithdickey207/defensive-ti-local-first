"""
Analysis Engine
---------------
Regex IoC extraction + local JSON signatures + simple heuristics.
All matching is local; no network calls.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SIG_DIR = ROOT / "data" / "signatures"

IOC_PATTERNS: Dict[str, Pattern[str]] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:[a-zA-Z]{2,24})\b"
    ),
}

_DOMAIN_NOISE = {
    "localhost",
    "localdomain",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
}

SUSPICIOUS_KEYWORDS = [
    "powershell",
    "frombase64string",
    "invoke-expression",
    "iex ",
    "mimikatz",
    "beacon",
    "cobalt",
    "meterpreter",
    "reverse shell",
    "cmd.exe",
    "wget ",
    "curl ",
    "nc -e",
    "ncat",
    "base64 -d",
    "certutil",
    "bitsadmin",
    "regsvr32",
    "mshta",
    "rundll32",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def load_signatures(sig_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    directory = Path(sig_dir or DEFAULT_SIG_DIR)
    sigs: List[Dict[str, Any]] = []
    if not directory.is_dir():
        return sigs
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for item in data.get("signatures", []):
            try:
                item = dict(item)
                item["_compiled"] = re.compile(item["pattern"])
                item["_source_file"] = path.name
                sigs.append(item)
            except (KeyError, re.error):
                continue
    return sigs


class Analyzer:
    def __init__(self, sig_dir: Optional[Path] = None) -> None:
        self.signatures = load_signatures(sig_dir)

    def extract_iocs(self, text: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        seen = set()
        for kind, pattern in IOC_PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(0)
                if kind == "domain":
                    low = val.lower()
                    if low in _DOMAIN_NOISE or low.endswith(".local"):
                        continue
                    if len(val) < 5:
                        continue
                key = (kind, val.lower() if kind != "cve" else val.upper())
                if key in seen:
                    continue
                seen.add(key)
                hits.append(
                    {
                        "kind": f"ioc_{kind}",
                        "indicator": val if kind != "cve" else val.upper(),
                        "severity": "medium" if kind in ("sha256", "cve") else "info",
                        "details": {"extractor": "regex"},
                    }
                )
        return hits

    def match_signatures(self, text: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for sig in self.signatures:
            compiled: Pattern[str] = sig["_compiled"]
            m = compiled.search(text)
            if m:
                hits.append(
                    {
                        "kind": "signature",
                        "indicator": sig.get("id", "unknown"),
                        "severity": sig.get("severity", "medium"),
                        "details": {
                            "name": sig.get("name"),
                            "category": sig.get("category"),
                            "match": m.group(0)[:120],
                            "source": sig.get("_source_file"),
                        },
                    }
                )
        return hits

    def heuristic_scan(self, text: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        low = text.lower()
        kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in low]
        if kw_hits:
            sev = "high" if len(kw_hits) >= 3 else "medium"
            hits.append(
                {
                    "kind": "heuristic_keywords",
                    "indicator": ",".join(kw_hits[:8]),
                    "severity": sev,
                    "details": {"count": len(kw_hits), "keywords": kw_hits},
                }
            )
        tokens = re.findall(r"[A-Za-z0-9+/=_-]{20,}", text)
        high_ent = []
        for tok in tokens[:50]:
            ent = shannon_entropy(tok)
            if ent >= 4.5 and len(tok) >= 24:
                high_ent.append({"token_preview": tok[:40], "entropy": round(ent, 3)})
        if high_ent:
            hits.append(
                {
                    "kind": "heuristic_entropy",
                    "indicator": f"{len(high_ent)}_high_entropy_tokens",
                    "severity": "low",
                    "details": {"samples": high_ent[:5]},
                }
            )
        return hits

    def analyze(self, text: str) -> List[Dict[str, Any]]:
        """Run full local analysis pipeline on one sanitized line/blob."""
        if not text or not text.strip():
            return []
        results: List[Dict[str, Any]] = []
        results.extend(self.extract_iocs(text))
        results.extend(self.match_signatures(text))
        results.extend(self.heuristic_scan(text))
        return results
