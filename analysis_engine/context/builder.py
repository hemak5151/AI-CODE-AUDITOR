"""Context packages for the LLM agents (the interface Member 3 consumes).

    build_context(project, target_id, flow=None, budget_tokens=2000) -> ContextPackage

`target_id` is a call-graph node id such as "app/db.py::Db.get_user"
(or "app/db.py::<module>" for top-level code). The package holds structured lists
(callers, callees, imports, taint_path) plus `token_trimmed_context`: ready-to-prompt text
that is guaranteed to fit the token budget. Sections are added in priority order:

    1 target function body   2 taint path   3 call sites of callers
    4 callee signatures      5 imports

Token counts default to a fast estimate (characters / 4). Pass `count_tokens` to use a real
tokenizer, for example the one that matches the model being prompted.
"""
import math
from typing import Callable, Optional

from analysis_engine.graph.callgraph import MODULE_NODE
from analysis_engine.project import Project
from shared.schemas import ContextPackage

MAX_LIST = 25


def estimate_tokens(text: str) -> int:
    return math.ceil(len(text) / 4)


def _split(node_id: str) -> tuple:
    path, _, qn = node_id.partition("::")
    return path, qn


def _numbered(lines: list, start: int, end: int) -> str:
    return "\n".join(f"{i:>4} | {lines[i - 1]}" for i in range(max(start, 1), min(end, len(lines)) + 1))


def target_for_line(project: Project, path: str, line: int) -> str:
    """Call-graph node id of the innermost function containing `line` (or the module node)."""
    best = None
    for fn in project.file_map[path].functions:
        if fn.start_line <= line <= fn.end_line:
            if best is None or (fn.end_line - fn.start_line) < (best.end_line - best.start_line):
                best = fn
    return f"{path}::{best.qualified_name}" if best else f"{path}::{MODULE_NODE}"


def _imports(project: Project, path: str) -> list:
    out = set()
    for imp in project.file_map[path].imports:
        if imp.names:
            out.update(f"{imp.module}.{n}" if not imp.module.endswith(".") else f"{imp.module}{n}" for n in imp.names)
        else:
            out.add(imp.module)
    return sorted(out)[:40]


def build_context(project: Project, target_id: str, flow=None, budget_tokens: int = 2000,
                  count_tokens: Callable[[str], int] = estimate_tokens) -> ContextPackage:
    graph = project.call_graph
    path, qn = _split(target_id)
    lines = project.lines(path)
    info = next((f for f in project.file_map[path].functions if f.qualified_name == qn), None)
    sink_line = flow.sink_line if flow is not None and flow.sink_file == path else None

    callers = sorted(graph.predecessors(target_id))[:MAX_LIST] if target_id in graph else []
    callees = sorted(graph.successors(target_id))[:MAX_LIST] if target_id in graph else []
    taint_path = [s.fmt() for s in flow.steps] if flow is not None else []

    remaining = budget_tokens
    parts: list = []

    def add(text: str) -> bool:
        nonlocal remaining
        cost = count_tokens(text) + 1
        if cost > remaining:
            return False
        parts.append(text)
        remaining -= cost
        return True

    # 1. target body (windowed around the sink if it does not fit in 60% of the budget)
    if info is not None:
        start, end = info.start_line, info.end_line
        title = f"## Target: {target_id} (lines {start}-{end})"
    else:
        center = sink_line or 1
        start, end = max(center - 15, 1), min(center + 15, len(lines))
        title = f"## Target: top-level code of {path} (lines {start}-{end})"
    body = _numbered(lines, start, end)
    if count_tokens(body) > budget_tokens * 0.6:
        keep = {start, min(start + 1, end)}
        center = sink_line or (start + end) // 2
        keep.update(range(max(center - 8, start), min(center + 8, end) + 1))
        chunks, previous = [], None
        for i in sorted(keep):
            if previous is not None and i != previous + 1:
                chunks.append("     | ... (lines omitted)")
            chunks.append(f"{i:>4} | {lines[i - 1]}")
            previous = i
        body = "\n".join(chunks)
        while count_tokens(body) > budget_tokens * 0.6 and len(chunks) > 3:  # last resort: shrink the window
            chunks.pop(-2)
            body = "\n".join(chunks)
    add(f"{title}\n{body}")

    # 2. taint path
    if taint_path:
        add("## Taint path (source -> sink)\n" + "\n".join(f"- {s}" for s in taint_path))

    # 3. call sites in callers
    site_blocks = []
    for caller in callers:
        cpath, _ = _split(caller)
        for line in graph[caller][target_id].get("lines", [])[:2]:
            clines = project.lines(cpath)
            site_blocks.append(f"# {caller} calls this at line {line}\n{_numbered(clines, line - 1, line + 1)}")
    if site_blocks:
        header_added = add("## Call sites")
        for block in site_blocks:
            if not header_added or not add(block):
                break

    # 4. callee signatures
    sig_blocks = []
    for callee in callees:
        cpath, cqn = _split(callee)
        cinfo = next((f for f in project.file_map[cpath].functions if f.qualified_name == cqn), None)
        if cinfo is not None:
            clines = project.lines(cpath)
            doc = f"    # {cinfo.docstring.splitlines()[0]}" if cinfo.docstring else ""
            sig_blocks.append(f"# {callee}\n{clines[cinfo.start_line - 1].strip()}{doc}")
    if sig_blocks:
        header_added = add("## Called functions (signatures)")
        for block in sig_blocks:
            if not header_added or not add(block):
                break

    # 5. imports
    imports = _imports(project, path)
    if imports:
        text = "## Imports\n" + ", ".join(imports)
        if not add(text):
            add("## Imports\n" + ", ".join(imports[:8]) + ", ...")

    return ContextPackage(target_function=target_id, callers=callers, callees=callees, imports=imports,
                          taint_path=taint_path, token_trimmed_context="\n\n".join(parts))
