# AI-Powered Code Refactoring & Security Compliance Auditor — Starter

A runnable foundation for a four-member 10-week project. This repository deliberately implements an early core-build stage rather than pretending the advanced RAG/agentic/security system is complete.

## What works now
- FastAPI backend with `/api/health` and `/api/analyze`.
- Python AST parsing: functions, classes, imports, line ranges and parse errors.
- Deterministic starter security checks for `eval`, `exec`, `shell=True`, and credential-like literals.
- One shared Pydantic `Finding` contract.
- Member 1 → Member 3 `ContextPackage` contract.
- Member 2 → Member 3 `RetrievalResponse` contract with dependency-light Markdown chunking and in-memory retrieval.
- Member 3 → Member 4 `Patch`/unified-diff contract and mock LLM provider.
- Member 3 → Member 2 `RunLog` model and Member 2 → Member 4 CSV/JSON examples.
- Next.js dashboard communicating with FastAPI and displaying findings.
- Pytest coverage for the vertical slice and interfaces.
- GitHub Actions backend tests and frontend build.
- Docker Compose foundation.

## Not implemented yet
Tree-Sitter multi-language parsing, call graphs, taint analysis, Semgrep/Bandit execution, vector/BM25/hybrid retrieval, embeddings, ChromaDB, Ollama/Qwen, LangGraph, autonomous patching, sandbox execution, self-repair, production queues, Monaco diff workflows, exports, and the full evaluation suite.

## Setup
### Backend
```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```
Backend: `http://localhost:8000` and docs: `http://localhost:8000/docs`.

### Frontend
Requires Node.js 22+.
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:3000`. If the backend is not on localhost:8000, set `NEXT_PUBLIC_API_URL` in the frontend environment.

### Tests
From repository root:
```bash
pytest -q
```
Frontend production check:
```bash
cd frontend
npm run build
```

### Docker
```bash
docker compose up --build
```

## Repository structure
- `analysis_engine/` — Member 1 analysis foundation.
- `rag/` — Member 2 ingestion/chunking/retrieval foundation.
- `agent/` — Member 3 model/agent/patch/validation foundation.
- `backend/` — Member 4 API integration.
- `frontend/` — Member 4 UI foundation.
- `shared/schemas/` — cross-member contracts.
- `evaluation/` — result and run-log foundation.
- `docs/` — architecture documentation.
- `samples/` — small test input.

## GitHub collaboration
Use `main` as protected release branch and `develop` as integration branch. Suggested feature branches:
- `feature/analysis-engine`
- `feature/rag-evaluation`
- `feature/agentic-llm`
- `feature/full-stack`

Do not push directly to `main`. Open pull requests into `develop`, request review from affected members, run CI, then merge. Promote tested `develop` changes to `main` through a reviewed PR.

## Shared interfaces that must not change casually
1. `shared.schemas.Finding`
2. `shared.schemas.ContextPackage`
3. `shared.schemas.RetrievalResponse` / `RetrievalChunk`
4. `shared.schemas.Patch`
5. `shared.schemas.RunLog`

If a field needs to change, update all consumers and the interface tests in the same PR.
