from pathlib import Path
from rag.chunking.markdown import chunk_markdown

def load_markdown(path: str):
    p=Path(path)
    return chunk_markdown(p.read_text(encoding="utf-8"), p.name)
