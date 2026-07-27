#!/usr/bin/env python3
"""Smoke tests for defensive TI core (stdlib unittest)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.analyzer import Analyzer, shannon_entropy  # noqa: E402
from src.sanitize import sanitize_text, sanitize_lines  # noqa: E402
from src.storage import init_db, insert_detections, insert_telemetry, stats  # noqa: E402


class TestSanitize(unittest.TestCase):
    def test_neutralize_url(self) -> None:
        out = sanitize_text("visit https://evil.example/payload now")
        self.assertIn("[NEUTRALIZED_URL]", out)
        self.assertNotIn("https://", out)

    def test_strip_script(self) -> None:
        out = sanitize_text('<script>alert(1)</script> hello')
        self.assertIn("[STRIPPED_SCRIPT]", out)
        self.assertNotIn("alert", out)

    def test_null_bytes(self) -> None:
        out = sanitize_text("safe\x00evil")
        self.assertNotIn("\x00", out)
        self.assertIn("safe", out)

    def test_lines(self) -> None:
        lines = sanitize_lines("a\n\nb\n")
        self.assertEqual(lines, ["a", "b"])


class TestAnalyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.a = Analyzer(sig_dir=ROOT / "data" / "signatures")

    def test_ipv4(self) -> None:
        hits = self.a.extract_iocs("Beacon 203.0.113.55 online")
        kinds = {h["kind"] for h in hits}
        self.assertIn("ioc_ipv4", kinds)

    def test_hash(self) -> None:
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        hits = self.a.extract_iocs(f"hash={md5}")
        self.assertTrue(any(h["kind"] == "ioc_md5" for h in hits))

    def test_cve(self) -> None:
        hits = self.a.extract_iocs("exploit CVE-2024-1234")
        self.assertTrue(any(h["kind"] == "ioc_cve" for h in hits))

    def test_signature_powershell(self) -> None:
        hits = self.a.match_signatures(
            "attacker used powershell -EncodedCommand AAAA"
        )
        self.assertTrue(any(h["kind"] == "signature" for h in hits))

    def test_heuristic_keywords(self) -> None:
        hits = self.a.heuristic_scan("mimikatz and meterpreter beacon")
        self.assertTrue(any(h["kind"] == "heuristic_keywords" for h in hits))

    def test_entropy(self) -> None:
        self.assertGreater(shannon_entropy("abcabcabc"), 0)
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_full_analyze(self) -> None:
        text = (
            "Beacon 203.0.113.55 → evil-c2.example using powershell FromBase64String"
        )
        from src.sanitize import sanitize_text

        clean = sanitize_text(text)
        hits = self.a.analyze(clean)
        self.assertTrue(len(hits) >= 1)


class TestStorage(unittest.TestCase):
    def test_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "t.db"
            init_db(db)
            tid = insert_telemetry("line one", "test", raw_hash="abc", db_path=db)
            n = insert_detections(
                tid,
                [
                    {
                        "kind": "ioc_ipv4",
                        "indicator": "1.2.3.4",
                        "severity": "info",
                        "details": {},
                    }
                ],
                db_path=db,
            )
            self.assertEqual(n, 1)
            s = stats(db)
            self.assertEqual(s["telemetry_rows"], 1)
            self.assertEqual(s["detection_rows"], 1)


if __name__ == "__main__":
    unittest.main()
