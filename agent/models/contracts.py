from pydantic import BaseModel, Field
from typing import Optional
from shared.schemas import Finding, ContextPackage, RetrievalResponse, Patch


class LLMRequest(BaseModel):
    prompt: str
    context: Optional[str] = None
    response_format: Optional[dict] = None


class LLMResponse(BaseModel):
    content: str
    model: str = "mock-local"
    tokens: int = 0


class AgentInput(BaseModel):
    finding: Finding
    context: Optional[ContextPackage] = None
    retrieval: Optional[RetrievalResponse] = None


class AgentOutput(BaseModel):
    finding: Finding
    patch: Optional[Patch] = None