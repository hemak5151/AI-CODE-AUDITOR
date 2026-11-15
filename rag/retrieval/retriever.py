
import re

from shared.schemas import RetrievalChunk, RetrievalResponse
from rag.chunking.markdown import DocumentChunk


def _terms(text: str) -> set[str]:
    return {
        term
        for term in re.findall(r"[a-z0-9_]+", text.lower())
        if len(term) > 2
    }


class InMemoryRetriever:
    """Keyword retrieval with heading and security-term matching."""

    def __init__(self, chunks: list[DocumentChunk]):
        self.chunks = chunks

    def retrieve(self, query: str, top_k: int = 5) -> RetrievalResponse:
        query_terms = _terms(query)
        query_lower = query.lower()
        scored = []

        # Security-related synonyms and concepts
        concept_terms = {
            "Dynamic code execution": {
                "eval", "exec", "execute", "execution",
                "arbitrary", "untrusted", "code",
            },
            "Command execution": {
                "shell", "subprocess", "command", "process",
                "injection",
            },
            "Secrets": {
                "password", "credentials", "token", "tokens",
                "api", "key", "secret",
            },
            "SQL Injection": {
                "sql", "query", "database", "parameterized",
            },
            "Path Traversal": {
                "path", "traversal", "directory", "filename",
                "file", "files",
            },
            "Insecure File Handling": {
                "upload", "uploads", "filename", "file",
                "files", "handling",
            },
            "Unsafe Deserialization": {
                "pickle", "deserialize", "deserialization",
                "serialized", "untrusted", "data",
            },
        }

        for chunk in self.chunks:
            content_terms = _terms(chunk.content)
            heading_terms = _terms(chunk.section)

            content_matches = len(query_terms & content_terms)
            heading_matches = len(query_terms & heading_terms)

            concept_matches = len(
                query_terms & concept_terms.get(chunk.section, set())
            )

            score = (
                content_matches
                + 2 * heading_matches
                + concept_matches
            ) / max(len(query_terms), 1)

            # Give a stronger signal to deserialization-related queries
            if chunk.section == "Unsafe Deserialization":
                if query_terms & {
                    "deserialize",
                    "deserialization",
                    "serialized",
                    "pickle",
                }:
                    score += 1.0

            # Recognize the ../ path traversal pattern
            if chunk.section == "Path Traversal" and "../" in query:
                score += 0.5

            if score > 0:
                scored.append((score, chunk))

        scored.sort(key=lambda item: item[0], reverse=True)

        return RetrievalResponse(
            query=query,
            chunks=[
                RetrievalChunk(
                    source=chunk.source,
                    section=chunk.section,
                    score=round(score, 4),
                    content=chunk.content,
                )
                for score, chunk in scored[:top_k]
            ],
        )
