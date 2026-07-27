#!/usr/bin/env python3
"""
CLI for Defensive Threat Intelligence local-first pipeline.

  python3 -m src.main              # run full pipeline
  python3 -m src.main --stats
  python3 -m src.main --recent 20
  python3 -m src.main --once "line of log text"
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from .ingest import (
    DEFAULT_INCOMING,
    LISTEN_HOST,
    LISTEN_PORT,
    feed_text,
    start_localhost_listener,
    watch_incoming,
)
from .pipeline import Pipeline
from .storage import init_db, recent_detections, stats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("main")


def _fmt_ts(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def cmd_stats() -> int:
    init_db()
    s = stats()
    print("=== Local TI Stats ===")
    print(f"Telemetry rows : {s['telemetry_rows']}")
    print(f"Detections     : {s['detection_rows']}")
    if s["by_kind"]:
        print("By kind:")
        for k, n in s["by_kind"].items():
            print(f"  {k:28s} {n}")
    if s["by_severity"]:
        print("By severity:")
        for k, n in s["by_severity"].items():
            print(f"  {k:28s} {n}")
    return 0


def cmd_recent(limit: int) -> int:
    init_db()
    rows = recent_detections(limit)
    if not rows:
        print("No detections yet.")
        return 0
    print(f"=== Recent detections (limit {limit}) ===")
    for r in rows:
        print(
            f"[{_fmt_ts(r['detected_at'])}] "
            f"sev={r['severity']:6s} kind={r['kind']:22s} "
            f"ioc={r['indicator'][:60]}"
        )
        print(f"    source={r['source']}  text={r['sanitized'][:100]!r}")
    return 0


async def run_pipeline(once: str | None = None, no_tcp: bool = False) -> None:
    pipe = Pipeline(workers=2)
    await pipe.start()

    stop_event = asyncio.Event()

    def _handle_sig(*_args):
        log.info("Shutdown signal received")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            pass

    server = None
    tasks = []

    if once:
        n = await feed_text(pipe.queue, once, source="cli:--once")
        log.info("Queued %d line(s) from --once", n)
        await pipe.queue.join()
        await pipe.stop()
        return

    tasks.append(asyncio.create_task(watch_incoming(pipe.queue, DEFAULT_INCOMING)))

    if not no_tcp:
        try:
            server = await start_localhost_listener(pipe.queue, LISTEN_HOST, LISTEN_PORT)
        except OSError as exc:
            log.warning("TCP listener not started (%s) — file drop still works", exc)

    print("=" * 60)
    print(" Defensive TI Local-First Pipeline")
    print(" Air-gapped · defensive only · MIT License")
    print("=" * 60)
    print(f" Drop files → {DEFAULT_INCOMING}")
    if server:
        print(f" Local TCP  → {LISTEN_HOST}:{LISTEN_PORT}  (nc / printf only)")
    print(" Ctrl+C to stop")
    print("=" * 60)

    await stop_event.wait()

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    if server:
        server.close()
        await server.wait_closed()
    await pipe.stop()
    log.info("Pipeline stopped cleanly")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Defensive local-first threat intelligence pipeline"
    )
    parser.add_argument("--stats", action="store_true", help="Show DB stats and exit")
    parser.add_argument(
        "--recent",
        type=int,
        metavar="N",
        nargs="?",
        const=20,
        help="Show N most recent detections (default 20)",
    )
    parser.add_argument(
        "--once",
        metavar="TEXT",
        help="Analyze a single text blob and exit (no long-running server)",
    )
    parser.add_argument(
        "--no-tcp",
        action="store_true",
        help="Disable localhost TCP listener (file drop only)",
    )
    args = parser.parse_args(argv)

    if args.stats:
        return cmd_stats()
    if args.recent is not None:
        return cmd_recent(args.recent)

    try:
        asyncio.run(run_pipeline(once=args.once, no_tcp=args.no_tcp))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
