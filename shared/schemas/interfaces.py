"""Cross-member contracts. Keep these stable and change only by team agreement."""
from typing import List, Optional
from pydantic import BaseModel, Field
from .finding import Finding

class ContextPackage(BaseModel):
    target_function: str
    callers: List[str] = Field(default_factory=list)
    callees: List[str] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    taint_path: List[str] = Field(default_factory=list)
    token_trimmed_context: str = ""

class RetrievalChunk(BaseModel):
    source: str
    section: str
    score: float
    content: str

class RetrievalResponse(BaseModel):
    query: str
    chunks: List[RetrievalChunk]

class Patch(BaseModel):
    finding_id: str
    unified_diff: Optional[str] = None
    description: str

class AnalysisResult(BaseModel):
    findings: List[Finding]
    functions: List[str] = []
    classes: List[str] = []
    imports: List[str] = Field(default_factory=list)
    parse_error: Optional[str] = None
    context: Optional[ContextPackage] = None

class RunLog(BaseModel):
    model: str
    prompt_version: str
    seed: Optional[int] = None
    tokens: Optional[int] = None
    latency_ms: Optional[float] = None
    commit_hash: Optional[str] = None
    date: str

class EvaluationResult(BaseModel):
    run_id: str
    dataset: str
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None
    findings: List[Finding] = Field(default_factory=list)
