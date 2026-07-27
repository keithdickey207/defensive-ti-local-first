# Bookmark history for local LLM learning

## Tools (repo root)

| File | Purpose |
|------|--------|
| `bookmark_ingest.py` | Parse Chrome JSON / Netscape HTML bookmarks → local SQLite |
| `rag_loader.py` | Embed docs with Ollama `nomic-embed-text` → local vector SQLite |

## Quick start

```bash
# Export Chrome bookmarks → drop into Linux:
# ~/shared/inbox/bookmarks.html

python3 bookmark_ingest.py --auto
python3 bookmark_ingest.py --stats
python3 bookmark_ingest.py --rag-export
python3 rag_loader.py --latest
python3 rag_loader.py --query "threat intelligence air gap"
```

If these scripts are not yet on a shallow clone, they are part of the full
source tree under `~/projects/defensive-ti-local-first/` on the author machine.

All network activity is **localhost only** (Ollama on `127.0.0.1:11434`).
