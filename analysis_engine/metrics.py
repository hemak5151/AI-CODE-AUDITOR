"""Per-function complexity metrics and code smells.

  loc          physical lines of the function
  params       parameters, not counting self/cls
  cyclomatic   1 + decision points (if/elif, loops, except/catch, case, ?:, and/or, comprehension filters)
  max_nesting  deepest nesting of if/loops/try/with/switch (an `else if` chain counts as one level)
Nested named functions are measured on their own, not inside their parent.
"""
import hashlib
from typing import Optional

from pydantic import BaseModel, Field

from analysis_engine.project import FUNC_TYPES, Project
from shared.schemas import Finding, LineRange, Severity

THRESHOLDS = {"long-function": 60, "too-many-params": 5, "high-complexity": 10, "deep-nesting": 4}

DECISIONS = {
    "python": {"if_statement", "elif_clause", "for_statement", "while_statement", "except_clause",
               "conditional_expression", "for_in_clause", "if_clause", "case_clause", "boolean_operator"},
    "javascript": {"if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement",
                   "switch_case", "catch_clause", "ternary_expression"},
}
JS_LOGICAL = {"&&", "||", "??"}
NESTING = {
    "python": {"if_statement", "for_statement", "while_statement", "try_statement", "with_statement", "match_statement"},
    "javascript": {"if_statement", "for_statement", "for_in_statement", "while_statement", "do_statement",
                   "try_statement", "switch_statement"},
}


class FunctionMetrics(BaseModel):
    file_path: str
    qualified_name: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    loc: int
    params: int
    cyclomatic: int
    max_nesting: int
    smells: list[str] = Field(default_factory=list)


def _measure(node, language: str, known: set) -> tuple:
    decisions, nesting = DECISIONS[language], NESTING[language]
    kinds = FUNC_TYPES[language]
    cyclomatic, deepest = 1, 0
    stack = [(node, 0)]
    while stack:
        n, depth = stack.pop()
        if n is not node and n.type in kinds and (n.start_point[0] + 1, n.end_point[0] + 1) in known:
            continue  # measured separately
        if n.type in decisions:
            cyclomatic += 1
        elif language == "javascript" and n.type == "binary_expression":
            op = n.child_by_field_name("operator")
            if op is not None and op.type in JS_LOGICAL:
                cyclomatic += 1
        child_depth = depth
        if n.type in nesting:
            child_depth = depth + 1
            deepest = max(deepest, child_depth)
        for child in reversed(n.children):
            d = child_depth
            if n.type == "else_clause" and child.type == "if_statement":
                d = depth - 1  # `else if` is a flat chain, not deeper nesting
            stack.append((child, max(d, 0)))
    return cyclomatic, deepest


def compute_metrics(project: Project, thresholds: Optional[dict] = None, paths=None) -> list:
    limits = {**THRESHOLDS, **(thresholds or {})}
    out = []
    for path in (sorted(project.file_map) if paths is None else [p for p in paths if p in project.file_map]):
        f = project.file_map[path]
        if f.language not in DECISIONS:
            continue
        known = {(fn.start_line, fn.end_line) for fn in f.functions}
        for fn in f.functions:
            node = project.function_node(path, fn)
            if node is None:
                continue
            cyclomatic, nesting = _measure(node, f.language, known)
            params = len([p for p in fn.params if p not in ("self", "cls")])
            loc = fn.end_line - fn.start_line + 1
            smells = []
            if loc > limits["long-function"]:
                smells.append("long-function")
            if params > limits["too-many-params"]:
                smells.append("too-many-params")
            if cyclomatic > limits["high-complexity"]:
                smells.append("high-complexity")
            if nesting > limits["deep-nesting"]:
                smells.append("deep-nesting")
            out.append(FunctionMetrics(file_path=path, qualified_name=fn.qualified_name, start_line=fn.start_line,
                                       end_line=fn.end_line, loc=loc, params=params, cyclomatic=cyclomatic,
                                       max_nesting=nesting, smells=smells))
    return sorted(out, key=lambda m: (m.file_path, m.start_line))


def smell_findings(metrics: list, thresholds: Optional[dict] = None) -> list:
    """Turn smells into Finding objects (no CWE) so the refactoring agent can consume them."""
    limits = {**THRESHOLDS, **(thresholds or {})}
    text = {
        "long-function": lambda m: f"is {m.loc} lines long (limit {limits['long-function']})",
        "too-many-params": lambda m: f"takes {m.params} parameters (limit {limits['too-many-params']})",
        "high-complexity": lambda m: f"has cyclomatic complexity {m.cyclomatic} (limit {limits['high-complexity']})",
        "deep-nesting": lambda m: f"nests {m.max_nesting} levels deep (limit {limits['deep-nesting']})",
    }
    out = []
    for m in metrics:
        for smell in m.smells:
            out.append(Finding(
                finding_id=f"smell-{smell}-{hashlib.sha1((m.file_path + m.qualified_name).encode()).hexdigest()[:8]}",
                cwe_id=None, severity=Severity.INFO, confidence=1.0,
                message=f"Code smell ({smell}): {m.qualified_name}",
                explanation=f"{m.qualified_name}() {text[smell](m)}. Consider splitting it into smaller functions.",
                file_path=m.file_path, line_number=m.start_line,
                line_range=LineRange(start=m.start_line, end=m.end_line),
                evidence=f"loc={m.loc} params={m.params} cyclomatic={m.cyclomatic} nesting={m.max_nesting}",
                source="metrics", suggested_remediation="Extract helper functions and reduce branching."))
    return out
