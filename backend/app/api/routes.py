from fastapi import APIRouter, HTTPException
from backend.app.models.api import AnalyzeRequest, AnalyzeResponse, HealthResponse
from backend.app.services.analyzer import analyze
router=APIRouter()

@router.get("/health", response_model=HealthResponse)
def health(): return HealthResponse(status="ok", service="code-auditor-backend")

@router.post("/analyze", response_model=AnalyzeResponse)
def analyze_code(request: AnalyzeRequest):
    result=analyze(request.code)
    if result.parse_error:
        raise HTTPException(status_code=422, detail={"message":"Python parse error","parse_error":result.parse_error})
    payload=result.model_dump(exclude={"context"})
    for finding in payload["findings"]:
        finding["file_path"] = request.filename
    return AnalyzeResponse(filename=request.filename, **payload)
