"""Load and validate the YAML rule files."""
from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, model_validator

RULES_DIR = Path(__file__).parent / "rule_data"


class SinkSpec(BaseModel):
    match: list[str]
    args: Union[list[int], Literal["all"]] = Field(default_factory=lambda: [0])
    requires_kw: dict[str, str] = Field(default_factory=dict)         # keyword must equal this text (case-insensitive)
    unless_kw: dict[str, list[str]] = Field(default_factory=dict)     # skip when keyword value ends with one of these


class SanitizerSpec(BaseModel):
    match: list[str]
    clears: Union[list[str], Literal["all"]]


class CweInfo(BaseModel):
    name: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float = 0.9
    remediation: str


class LanguageRules(BaseModel):
    sources: list[str]
    sanitizers: list[SanitizerSpec] = Field(default_factory=list)
    sinks: dict[str, list[SinkSpec]] = Field(default_factory=dict)


class SecretRules(BaseModel):
    name_hints: list[str]
    weak_name_hints: list[str] = Field(default_factory=list)
    min_length: int = 4
    name_ignore_hints: list[str] = Field(default_factory=list)
    placeholders: list[str] = Field(default_factory=list)


class TaintRules(BaseModel):
    version: int
    risky_call_cwes: list[str] = Field(default_factory=list)
    risky_call_confidence_factor: float = 0.55
    cwes: dict[str, CweInfo]
    languages: dict[str, LanguageRules]
    secrets: SecretRules

    @model_validator(mode="after")
    def _sinks_use_known_cwes(self):
        for lang, rules in self.languages.items():
            for cwe in rules.sinks:
                if cwe not in self.cwes:
                    raise ValueError(f"{lang}: sink uses unknown CWE {cwe}")
        return self


class DeprecatedItem(BaseModel):
    kind: Literal["module", "call", "attribute"]
    match: str
    since: Optional[str] = None
    removed: Optional[str] = None
    replacement: str


class DeprecatedRules(BaseModel):
    version: int
    languages: dict[str, list[DeprecatedItem]]


@lru_cache(maxsize=None)
def load_taint_rules(path: Optional[str] = None) -> TaintRules:
    text = Path(path or RULES_DIR / "taint.yaml").read_text(encoding="utf-8")
    return TaintRules.model_validate(yaml.safe_load(text))


@lru_cache(maxsize=None)
def load_deprecated_rules(path: Optional[str] = None) -> DeprecatedRules:
    text = Path(path or RULES_DIR / "deprecated.yaml").read_text(encoding="utf-8")
    return DeprecatedRules.model_validate(yaml.safe_load(text))
