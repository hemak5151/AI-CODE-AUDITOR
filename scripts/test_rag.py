from rag.ingestion.loader import load_markdown
from rag.retrieval import InMemoryRetriever

# Load your security guideline document
chunks = load_markdown("rag/data/python-security.md")

# Create the retriever
retriever = InMemoryRetriever(chunks)

# Questions to test
queries = [
    "eval untrusted input",
    "shell=True subprocess commands",
    "hardcoded passwords API keys tokens",
]
# Search for relevant guideline chunks
for query in queries:
    result = retriever.retrieve(query, top_k=3)

    print(f"\nQuery: {query}")

    for chunk in result.chunks:
        print(f"Score: {chunk.score}")
        print(f"Section: {chunk.section}")
        print(chunk.content)
