from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.routes import router
from backend.app.core.config import settings
app=FastAPI(title="AI Code Refactoring & Security Auditor", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=[settings.cors_origin,"http://localhost:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router, prefix="/api")
