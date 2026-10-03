# Starter architecture

```text
Next.js UI
   │ POST /api/analyze
   ▼
FastAPI
   │
   ▼
Analysis Engine ──> shared Finding schema
   │                       │
   └──> ContextPackage ────┘

RAG ──> RetrievalResponse ──> future agent workflow
Agent ──> Patch/unified diff ──> API/UI
Evaluation ──> RunLog + CSV/JSON results
```

The current vertical slice intentionally uses Python `ast`, deterministic checks, in-memory retrieval, and a mock LLM provider. Advanced technologies are extension points rather than runtime requirements.
