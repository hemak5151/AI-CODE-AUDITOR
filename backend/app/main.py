from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.routes import router
from backend.app.api.job_routes import router as job_router
from backend.app.api.guideline_routes import router as guideline_router
from backend.app.api.export_routes import router as export_router
from backend.app.api.file_routes import router as file_router
from backend.app.core.config import settings

app = FastAPI(title="AI Code Refactoring & Security Auditor", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origin, "http://localhost:3000"],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")
app.include_router(job_router, prefix="/api")
app.include_router(guideline_router, prefix="/api")
app.include_router(export_router, prefix="/api")
app.include_router(file_router, prefix="/api")