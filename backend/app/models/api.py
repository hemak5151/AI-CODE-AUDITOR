from pydantic import BaseModel
from shared.schemas import AnalysisResult
class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "submitted.py"
class HealthResponse(BaseModel):
    status: str
    service: str
class AnalyzeResponse(AnalysisResult):
    filename: str
