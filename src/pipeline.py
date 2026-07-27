"""
Asynchronous Pipeline
---------------------
asyncio queue + worker pool: sanitize already done at ingest → analyze → store.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from .analyzer import Analyzer
from .storage import init_db, insert_detections, insert_telemetry

log = logging.getLogger("pipeline")


class Pipeline:
    def __init__(
        self,
        workers: int = 2,
        db_path: Optional[Path] = None,
        sig_dir: Optional[Path] = None,
    ) -> None:
        self.workers = max(1, workers)
        self.db_path = db_path
        self.analyzer = Analyzer(sig_dir=sig_dir)
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self._tasks: list[asyncio.Task] = []
        self._running = False

    def setup(self) -> None:
        path = init_db(self.db_path)
        log.info("Database ready → %s", path)
        log.info("Loaded %d local signatures", len(self.analyzer.signatures))

    async def worker(self, worker_id: int) -> None:
        log.info("Worker-%d started", worker_id)
        while self._running:
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            try:
                text = item.get("text", "")
                source = item.get("source", "unknown")
                raw_hash = item.get("raw_hash")
                tel_id = insert_telemetry(
                    sanitized=text,
                    source=source,
                    raw_hash=raw_hash,
                    db_path=self.db_path,
                )
                detections = self.analyzer.analyze(text)
                n = insert_detections(tel_id, detections, db_path=self.db_path)
                if n:
                    kinds = ", ".join(sorted({d["kind"] for d in detections}))
                    log.info(
                        "Worker-%d telemetry#%d → %d detection(s) [%s]",
                        worker_id,
                        tel_id,
                        n,
                        kinds,
                    )
            except Exception:
                log.exception("Worker-%d failed on item", worker_id)
            finally:
                self.queue.task_done()
        log.info("Worker-%d stopped", worker_id)

    async def start(self) -> None:
        self.setup()
        self._running = True
        self._tasks = [
            asyncio.create_task(self.worker(i + 1), name=f"worker-{i+1}")
            for i in range(self.workers)
        ]

    async def stop(self) -> None:
        self._running = False
        try:
            await asyncio.wait_for(self.queue.join(), timeout=5.0)
        except asyncio.TimeoutError:
            pass
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
