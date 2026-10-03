"""Shared Finding contract used across analysis, agent, API, and frontend layers."""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LineRange(BaseModel):
    start: int = Field(ge=1)
    end: int = Field(ge=1)

class Finding(BaseModel):
    finding_id: str
    cwe_id: Optional[str] = None
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    message: str
    explanation: str
    file_path: str
    line_number: int = Field(ge=1)
    line_range: Optional[LineRange] = None
    evidence: Optional[str] = None
    source: str
    suggested_remediation: Optional[str] = None
    patch: Optional[str] = None
