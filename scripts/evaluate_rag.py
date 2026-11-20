
import json
from pathlib import Path

from rag.ingestion.loader import load_markdown
from rag.retrieval import InMemoryRetriever


chunks = load_markdown("rag/data/python-security.md")
retriever = InMemoryRetriever(chunks)


test_cases = [
    # 1. Dynamic code execution
    ("eval untrusted input", "Dynamic code execution"),
    ("exec on user supplied data", "Dynamic code execution"),
    ("avoid evaluating arbitrary strings", "Dynamic code execution"),
    ("safer alternative to eval", "Dynamic code execution"),
    ("execute a string as Python code", "Dynamic code execution"),
    ("prevent arbitrary code execution", "Dynamic code execution"),
    ("Python eval security issue", "Dynamic code execution"),
    ("user input interpreted as code", "Dynamic code execution"),
    ("avoid executing arbitrary expressions", "Dynamic code execution"),
    ("parse input rather than execute it", "Dynamic code execution"),

    # 2. Command execution
    ("shell=True subprocess commands", "Command execution"),
    ("avoid shell injection", "Command execution"),
    ("safe subprocess arguments", "Command execution"),
    ("run external commands without a shell", "Command execution"),
    ("command injection vulnerability in Python", "Command execution"),
    ("use shell=False", "Command execution"),
    ("securely launch a system process", "Command execution"),
    ("shell command built from user input", "Command execution"),
    ("Python subprocess security risk", "Command execution"),
    ("prevent shell command injection", "Command execution"),

    # 3. Secrets
    ("hardcoded passwords API keys tokens", "Secrets"),
    ("store credentials safely", "Secrets"),
    ("remove passwords from source code", "Secrets"),
    ("use environment variables for secrets", "Secrets"),
    ("prevent API key leaks", "Secrets"),
    ("avoid committing access tokens", "Secrets"),
    ("password exposed in a Python file", "Secrets"),
    ("detect hardcoded authentication secrets", "Secrets"),
    ("where should application secrets be stored", "Secrets"),
    ("protect private API tokens", "Secrets"),

    # 4. SQL Injection
    ("SQL injection vulnerability", "SQL Injection"),
    ("prevent SQL injection attacks", "SQL Injection"),
    ("unsafe SQL query construction", "SQL Injection"),
    ("user input inserted into SQL query", "SQL Injection"),
    ("use parameterized SQL queries", "SQL Injection"),
    ("prepared statements for database security", "SQL Injection"),
    ("SQL query built using string concatenation", "SQL Injection"),
    ("attacker modifies database queries", "SQL Injection"),
    ("secure database query practices", "SQL Injection"),
    ("avoid formatting SQL with untrusted input", "SQL Injection"),

    # 5. Path Traversal
    ("path traversal vulnerability", "Path Traversal"),
    ("prevent directory traversal attacks", "Path Traversal"),
    ("user input controls file paths", "Path Traversal"),
    ("access files outside allowed directory", "Path Traversal"),
    ("validate user supplied file paths", "Path Traversal"),
    ("attack using ../ in a filename", "Path Traversal"),
    ("restrict file access to a directory", "Path Traversal"),
    ("unsafe file path supplied by a user", "Path Traversal"),
    ("resolve paths within an allowed folder", "Path Traversal"),
    ("prevent unauthorized file access", "Path Traversal"),

    # 6. Insecure File Handling
    ("insecure file upload handling", "Insecure File Handling"),
    ("validate uploaded file types", "Insecure File Handling"),
    ("malicious file upload security", "Insecure File Handling"),
    ("restrict uploaded file sizes", "Insecure File Handling"),
    ("generate safe filenames for uploads", "Insecure File Handling"),
    ("avoid trusting user supplied filenames", "Insecure File Handling"),
    ("store uploads outside public directories", "Insecure File Handling"),
    ("unsafe file operations", "Insecure File Handling"),
    ("prevent unauthorized file uploads", "Insecure File Handling"),
    ("securely process uploaded files", "Insecure File Handling"),

    # 7. Unsafe Deserialization
    ("unsafe pickle deserialization", "Unsafe Deserialization"),
    ("never load untrusted pickle data", "Unsafe Deserialization"),
    ("pickle.loads security vulnerability", "Unsafe Deserialization"),
    ("deserialize untrusted user input", "Unsafe Deserialization"),
    ("arbitrary code execution through pickle", "Unsafe Deserialization"),
    ("use JSON instead of pickle for untrusted data", "Unsafe Deserialization"),
    ("safe handling of serialized data", "Unsafe Deserialization"),
    ("untrusted serialized Python objects", "Unsafe Deserialization"),
    ("validate data after deserialization", "Unsafe Deserialization"),
    ("prevent malicious pickle payloads", "Unsafe Deserialization"),
]


k = 3
hits = 0
reciprocal_ranks = []
details = []

for query, expected_section in test_cases:
    result = retriever.retrieve(query, top_k=k)
    sections = [chunk.section for chunk in result.chunks]

    rank = next(
        (
            i
            for i, section in enumerate(sections, start=1)
            if section == expected_section
        ),
        None,
    )

    hit = rank is not None
    hits += int(hit)
    reciprocal_ranks.append(1 / rank if hit else 0)

    details.append({
        "query": query,
        "expected_section": expected_section,
        "retrieved_sections": sections,
        "relevant_rank": rank,
        "hit_at_k": hit,
    })

recall_at_k = hits / len(test_cases)
mrr = sum(reciprocal_ranks) / len(test_cases)

report = {
    "num_queries": len(test_cases),
    "k": k,
    "recall_at_k": round(recall_at_k, 4),
    "mrr": round(mrr, 4),
    "results": details,
}

Path("evaluation").mkdir(exist_ok=True)
Path("evaluation/rag_baseline.json").write_text(
    json.dumps(report, indent=2),
    encoding="utf-8",
)
print("\nQueries that failed to retrieve the expected section:")

for item in details:
    if not item["hit_at_k"]:
        print(f"\nQuery: {item['query']}")
        print(f"Expected: {item['expected_section']}")
        print(f"Retrieved: {item['retrieved_sections']}")
print(f"Number of queries: {len(test_cases)}")
print(f"Recall@{k}: {recall_at_k:.2%}")
print(f"MRR: {mrr:.4f}")
print("Saved report to evaluation/rag_baseline.json")
