"""Normalized structure models (Member 1). Output of the structure extractor."""
from typing import Literal, Optional

from pydantic import BaseModel, Field


class CallInfo(BaseModel):
    """One call site, as written in the source (e.g. "helper", "self.get", "os.path.join")."""
    name: str
    line: int = Field(ge=1)


class ImportInfo(BaseModel):
    module: str
    names: list[str] = Field(default_factory=list)
    alias: Optional[str] = None
    # local alias -> imported name, e.g. "from x import a as b" gives {"b": "a"}
    local_names: dict[str, str] = Field(default_factory=dict)
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
    calls: list[CallInfo] = Field(default_factory=list)


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
    module_calls: list[CallInfo] = Field(default_factory=list)  # calls outside any function
    parse_error: Optional[str] = None
