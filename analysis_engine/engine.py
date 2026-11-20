
from pathlib import Path

from shared.schemas import AnalysisResult
from .parser import parse_python
from .security import scan_python
from .context import build_context_package

from rag.ingestion.loader import load_markdown
from rag.retrieval.retriever import InMemoryRetriever


# Load the security knowledge base once
PROJECT_ROOT = Path(__file__).resolve().parent.parent
KNOWLEDGE_BASE_PATH = PROJECT_ROOT / "rag" / "data" / "python-security.md"

_chunks = load_markdown(str(KNOWLEDGE_BASE_PATH))
_retriever = InMemoryRetriever(_chunks)


def enrich_findings_with_rag(findings):
    enriched_findings = []

    for finding in findings:
        # Choose a query based on the detected vulnerability
        if finding.cwe_id == "CWE-95":
            query = "eval exec untrusted input dynamic code execution"
        elif finding.cwe_id == "CWE-78":
            query = "shell=True subprocess command execution"
        elif finding.cwe_id == "CWE-798":
            query = "hardcoded passwords API keys tokens secrets"
        else:
            enriched_findings.append(finding)
            continue

        retrieval = _retriever.retrieve(query, top_k=1)

        if retrieval.chunks:
            best_chunk = retrieval.chunks[0]

            updated_explanation = (
                f"{finding.explanation}\n\n"
                f"Relevant security guidance "
                f"({best_chunk.section}): "
                f"{best_chunk.content}"
            )

            finding = finding.model_copy(
                update={"explanation": updated_explanation}
            )

        enriched_findings.append(finding)

    return enriched_findings


def analyze_python(source: str) -> AnalysisResult:
    parsed = parse_python(source)

    if parsed.parse_error:
        return AnalysisResult(
            findings=[],
            parse_error=parsed.parse_error
        )

    findings = scan_python(parsed.tree, source)

    # Add relevant RAG guidance to detected findings
    findings = enrich_findings_with_rag(findings)

    target = parsed.functions[0] if parsed.functions else "module"

    context = build_context_package(
        target,
        parsed.functions,
        parsed.imports,
        source
    )

    return AnalysisResult(
        findings=findings,
        functions=parsed.functions,
        classes=parsed.classes,
        imports=parsed.imports,
        context=context
    )
