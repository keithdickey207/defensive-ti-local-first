"""
Ingest Layer
------------
1) Directory drop watcher: data/incoming/
2) Localhost-only TCP listener: 127.0.0.1:9999 (never 0.0.0.0)

No outbound network activity.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import AsyncIterator, Optional, Tuple

from .sanitize import sanitize_lines

log = logging.getLogger("ingest")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INCOMING = ROOT / "data" / "incoming"

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 9999


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def read_and_mark_file(path: Path) -> Tuple[str, list[str]]:
    """
    Read a drop file, sanitize lines, rename to *.processed so it is not re-read.
    Returns (source_label, sanitized_lines).
    """
    raw = path.read_text(encoding="utf-8", errors="replace")
    lines = sanitize_lines(raw)
    processed = path.with_name(path.name + ".processed")
    try:
        path.rename(processed)
    except OSError as exc:
        log.warning("Could not rename %s → processed: %s", path, exc)
    return f"file:{path.name}", lines


async def watch_incoming(
    queue: asyncio.Queue,
    incoming: Optional[Path] = None,
    poll_seconds: float = 1.0,
) -> None:
    """Poll data/incoming/ for new files and push sanitized lines to the queue."""
    directory = Path(incoming or DEFAULT_INCOMING)
    directory.mkdir(parents=True, exist_ok=True)
    log.info("Watching drop directory → %s", directory)

    while True:
        try:
            for path in sorted(directory.iterdir()):
                if not path.is_file():
                    continue
                if path.name.startswith("."):
                    continue
                if path.name.endswith(".processed"):
                    continue
                if path.suffix == ".processed":
                    continue
                try:
                    source, lines = read_and_mark_file(path)
                except OSError as exc:
                    log.warning("Failed to read %s: %s", path, exc)
                    continue
                for line in lines:
                    await queue.put(
                        {
                            "source": source,
                            "text": line,
                            "raw_hash": _hash_text(line),
                        }
                    )
                if lines:
                    log.info("Ingested %d lines from %s", len(lines), path.name)
        except Exception as exc:
            log.exception("Incoming watcher error: %s", exc)
        await asyncio.sleep(poll_seconds)


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue,
) -> None:
    peer = writer.get_extra_info("peername")
    log.info("Local socket connection from %s", peer)
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            try:
                raw = data.decode("utf-8", errors="replace")
            except Exception:
                continue
            for line in sanitize_lines(raw):
                await queue.put(
                    {
                        "source": "tcp:127.0.0.1",
                        "text": line,
                        "raw_hash": _hash_text(line),
                    }
                )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_localhost_listener(
    queue: asyncio.Queue,
    host: str = LISTEN_HOST,
    port: int = LISTEN_PORT,
) -> asyncio.AbstractServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("Ingest listener must bind to localhost only")

    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, queue),
        host=host,
        port=port,
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    log.info("Localhost TCP listener on %s", addrs)
    return server


async def feed_text(
    queue: asyncio.Queue,
    text: str,
    source: str = "cli",
) -> int:
    """Push one multi-line blob into the queue (for tests / one-shot)."""
    n = 0
    for line in sanitize_lines(text):
        await queue.put(
            {
                "source": source,
                "text": line,
                "raw_hash": _hash_text(line),
            }
        )
        n += 1
    return n
