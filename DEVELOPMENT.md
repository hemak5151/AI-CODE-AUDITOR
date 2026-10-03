# Development ownership

## Member 1 — Analysis Engine & Baselines
Primary folders: `analysis_engine/`, `samples/` and analysis-related tests. Extend parsing, Tree-Sitter adapters, JavaScript/Java adapters, call graphs, taint analysis, context packaging, Semgrep/Bandit normalization.

## Member 2 — RAG, Data & Evaluation
Primary folders: `rag/`, `evaluation/`. Extend datasets, guideline ingestion, BM25/embeddings, ChromaDB, hybrid retrieval, reranking, metrics and experiment tracking.

## Member 3 — Agentic LLM & Patch Validation
Primary folders: `agent/`. Extend Ollama/Qwen provider, LangGraph agents, patch generation, verifier/critic, sandbox validation and self-repair.

## Member 4 — Full-Stack, DevOps & Paper
Primary folders: `backend/`, `frontend/`, `.github/`, `docker-compose.yml`, `docs/`. Extend uploads/jobs, dashboard, Monaco, exports, deployment and integration.

## Shared contract rule
`shared/schemas/` is owned jointly. Do not change `Finding`, `ContextPackage`, `RetrievalResponse`, `Patch`, or `RunLog` fields without agreement from all affected members and a test update.
