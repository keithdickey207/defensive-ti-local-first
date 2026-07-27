# Defensive Threat Intelligence Architecture (Local-First Blueprint)

Air-gapped, defensive-only pipeline for secure IoC / telemetry ingestion,
sanitization, heuristic & regex analysis, and local SQLite storage.

This project is intentionally limited to **defensive** operations inside an
isolated environment. No external reach-out, no active scanning of third-party
systems, and no automated egress is described or enabled.

**License:** MIT — see [LICENSE](LICENSE)  
**Author:** Keith Alan Dickey (2026)

---

## Requirements

- **Python 3.10+** (on ChromeOS / Penguin use `python3`, not `python`)
- Standard library only for the core pipeline
- Optional: [Ollama](https://ollama.com) + `nomic-embed-text` for bookmark RAG

```bash
python3 --version
```

## Project layout

```
defensive-ti-local-first/
├── LICENSE
├── README.md
├── ARCHITECTURE.md
├── requirements.txt          # empty / optional chromadb note
├── bookmark_ingest.py        # browser bookmarks → SQLite for LLM learning
├── rag_loader.py             # Ollama embeddings + local vector store
├── src/
│   ├── sanitize.py           # Sanitization buffer
│   ├── ingest.py             # File drop + localhost TCP
│   ├── analyzer.py           # Regex IoCs + signatures + heuristics
│   ├── storage.py            # SQLite WAL
│   ├── pipeline.py           # asyncio queue + workers
│   └── main.py               # CLI
├── data/
│   ├── incoming/             # Drop log files here
│   ├── signatures/           # Local JSON signatures
│   └── db/                   # SQLite (create at runtime)
├── loom_internal/            # Bookmark + RAG state
└── tests/test_core.py
```

---

## Quick start — threat pipeline

```bash
cd ~/defensive-ti-local-first   # symlink → projects/defensive-ti-local-first

# One-shot analysis (no long-running process)
python3 -m src.main --once "Beacon 203.0.113.55 using powershell FromBase64String"

# Inspect results
python3 -m src.main --stats
python3 -m src.main --recent 20

# Full pipeline (file drop + localhost TCP)
python3 -m src.main
```

In another terminal:

```bash
# Drop a log file
echo "Possible C2 on 10.0.0.55:4444 mimikatz" > data/incoming/test.log

# Or send via local socket only
printf '%s\n' "Beacon 203.0.113.55 evil" | nc 127.0.0.1 9999
# (if nc missing:)
printf '%s\n' "Beacon 203.0.113.55 evil" | python3 -c \
  "import socket,sys; s=socket.create_connection(('127.0.0.1',9999)); s.sendall(sys.stdin.buffer.read()); s.close()"
```

### Tests

```bash
python3 -m unittest tests.test_core -v
```

---

## Bookmark history for local LLM learning

ChromeOS Penguin usually **cannot** read Chrome’s live profile. Export once:

1. Chrome → `chrome://bookmarks` → **⋮** → **Export bookmarks**
2. Move the `.html` into Linux: `~/shared/inbox/bookmarks.html`
3. Ingest + prepare RAG docs:

```bash
cd ~/defensive-ti-local-first

python3 bookmark_ingest.py --auto
python3 bookmark_ingest.py --stats
python3 bookmark_ingest.py --rag-export

# Embed with local Ollama (nomic-embed-text already on this box)
python3 rag_loader.py --latest

# Query your personal knowledge base
python3 rag_loader.py --query "threat intelligence air gap"
```

Optional: if you install ChromaDB later:

```bash
pip install chromadb
python3 rag_loader.py --latest --chroma
```

---

## Hardening notes (from architecture)

| Control | How |
|---------|-----|
| Egress block | `sudo iptables -A OUTPUT -o eth0 -j DROP` (adjust interface) |
| Local bind only | TCP listener is **hard-coded** to `127.0.0.1` |
| Encrypted at rest | Put `data/db/` on an encrypted volume / fscrypt |
| Drop re-processing | Files in `data/incoming/` rename to `*.processed` after read |
| No remote IoC feeds | Signatures live only under `data/signatures/` |

---

## Architecture summary

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full local-first blueprint.

```
Raw logs → Sanitization → Async queue → Regex + Heuristics → SQLite → CLI reports
```

## Scope reminder

Defensive analysis only. This software does **not** perform offensive scanning,
external enrichment, or any automated outbound intelligence collection.
