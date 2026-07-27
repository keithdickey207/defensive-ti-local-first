"""
Storage Layer
-------------
Local SQLite (WAL) for telemetry + detections.
Put data/db/ on an encrypted volume for at-rest protection.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "db" / "ti_local.db"


def ensure_db_dir(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)


@contextmanager
def connect(db_path: Optional[Path] = None) -> Iterator[sqlite3.Connection]:
    path = Path(db_path or DEFAULT_DB)
    ensure_db_dir(path)
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: Optional[Path] = None) -> Path:
    path = Path(db_path or DEFAULT_DB)
    with connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS telemetry (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at   REAL NOT NULL,
                source        TEXT NOT NULL,
                raw_hash      TEXT,
                sanitized     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detections (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                telemetry_id  INTEGER NOT NULL,
                detected_at   REAL NOT NULL,
                kind          TEXT NOT NULL,
                indicator     TEXT NOT NULL,
                severity      TEXT NOT NULL DEFAULT 'info',
                details_json  TEXT,
                FOREIGN KEY (telemetry_id) REFERENCES telemetry(id)
            );

            CREATE INDEX IF NOT EXISTS idx_tel_received ON telemetry(received_at);
            CREATE INDEX IF NOT EXISTS idx_det_kind ON detections(kind);
            CREATE INDEX IF NOT EXISTS idx_det_severity ON detections(severity);
            CREATE INDEX IF NOT EXISTS idx_det_indicator ON detections(indicator);
            """
        )
    return path


def insert_telemetry(
    sanitized: str,
    source: str,
    raw_hash: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> int:
    now = time.time()
    with connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT INTO telemetry (received_at, source, raw_hash, sanitized)
            VALUES (?, ?, ?, ?)
            """,
            (now, source, raw_hash, sanitized),
        )
        return int(cur.lastrowid)


def insert_detections(
    telemetry_id: int,
    detections: List[Dict[str, Any]],
    db_path: Optional[Path] = None,
) -> int:
    if not detections:
        return 0
    now = time.time()
    with connect(db_path) as conn:
        for d in detections:
            conn.execute(
                """
                INSERT INTO detections
                    (telemetry_id, detected_at, kind, indicator, severity, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    telemetry_id,
                    now,
                    d.get("kind", "unknown"),
                    d.get("indicator", ""),
                    d.get("severity", "info"),
                    json.dumps(d.get("details") or {}, ensure_ascii=False),
                ),
            )
        return len(detections)


def recent_detections(limit: int = 20, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT d.id, d.detected_at, d.kind, d.indicator, d.severity,
                   d.details_json, t.source, t.sanitized
            FROM detections d
            JOIN telemetry t ON t.id = d.telemetry_id
            ORDER BY d.detected_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "detected_at": r["detected_at"],
                "kind": r["kind"],
                "indicator": r["indicator"],
                "severity": r["severity"],
                "details": json.loads(r["details_json"] or "{}"),
                "source": r["source"],
                "sanitized": r["sanitized"][:200],
            }
        )
    return out


def stats(db_path: Optional[Path] = None) -> Dict[str, Any]:
    with connect(db_path) as conn:
        tel = conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
        det = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        by_kind = conn.execute(
            """
            SELECT kind, COUNT(*) AS n FROM detections
            GROUP BY kind ORDER BY n DESC
            """
        ).fetchall()
        by_sev = conn.execute(
            """
            SELECT severity, COUNT(*) AS n FROM detections
            GROUP BY severity ORDER BY n DESC
            """
        ).fetchall()
    return {
        "telemetry_rows": tel,
        "detection_rows": det,
        "by_kind": {r["kind"]: r["n"] for r in by_kind},
        "by_severity": {r["severity"]: r["n"] for r in by_sev},
    }
