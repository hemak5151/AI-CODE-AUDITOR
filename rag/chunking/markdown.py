from dataclasses import dataclass
import re

@dataclass
class DocumentChunk:
    source: str
    section: str
    content: str

def chunk_markdown(text: str, source: str, max_chars: int = 700) -> list[DocumentChunk]:
    sections=re.split(r"(?m)^##?\s+(.+)$", text)
    chunks=[]
    if len(sections) == 1:
        return [DocumentChunk(source, "document", text.strip())] if text.strip() else []
    pre=sections[0].strip()
    if pre: chunks.append(DocumentChunk(source, "intro", pre[:max_chars]))
    for i in range(1, len(sections), 2):
        title=sections[i].strip(); body=sections[i+1].strip() if i+1<len(sections) else ""
        for start in range(0, len(body), max_chars):
            chunks.append(DocumentChunk(source, title, body[start:start+max_chars]))
    return chunks
