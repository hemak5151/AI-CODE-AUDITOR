import re
from shared.schemas import RetrievalChunk, RetrievalResponse
from rag.chunking.markdown import DocumentChunk

def _terms(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9_]+", text.lower()) if len(t) > 2}

class InMemoryRetriever:
    """Dependency-light retrieval; later replace scoring with BM25/vector/hybrid retrieval."""
    def __init__(self, chunks: list[DocumentChunk]):
        self.chunks = chunks

    def retrieve(self, query: str, top_k: int = 5) -> RetrievalResponse:
        terms = _terms(query)
        scored = []
        for chunk in self.chunks:
            words = _terms(chunk.content)
            score = sum(1 for term in terms if term in words) / max(len(terms), 1)
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda item: item[0], reverse=True)
        return RetrievalResponse(
            query=query,
            chunks=[
                RetrievalChunk(source=c.source, section=c.section, score=round(score, 4), content=c.content)
                for score, c in scored[:top_k]
            ],
        )
