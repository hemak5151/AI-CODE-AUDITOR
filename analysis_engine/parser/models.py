"""Normalized structure models (Member 1). Output of the structure extractor."""
from typing import Literal, Optional

from pydantic import BaseModel, Field


class ImportInfo(BaseModel):
    module: str
    names: list[str] = Field(default_factory=list)
    alias: Optional[str] = None
    line: int = Field(ge=1)


class FunctionInfo(BaseModel):
    name: str
    qualified_name: str
    kind: Literal["function", "method"]
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    params: list[str] = Field(default_factory=list)
    docstring: Optional[str] = None
    parent_class: Optional[str] = None


class ClassInfo(BaseModel):
    name: str
    qualified_name: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    bases: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    docstring: Optional[str] = None


class FileStructure(BaseModel):
    file_path: str
    language: str
    functions: list[FunctionInfo] = Field(default_factory=list)
    classes: list[ClassInfo] = Field(default_factory=list)
    imports: list[ImportInfo] = Field(default_factory=list)
    parse_error: Optional[str] = None
