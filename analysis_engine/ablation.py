"""Inputs for the C2 vs C3 ablation (does structural context help the LLM?).

    python -m analysis_engine.ablation <folder> --out ablation_inputs.jsonl [--budget 2000]

Every candidate function (one that calls something dangerous: SQL execution, shell, file open, deserialization,
eval; judged by name only, never by ground truth) gets the SAME code in each configuration:
    c2        the function's code only                                      (LLM only, raw code)
    c3        + callers' call sites, callees' signatures, imports            (AST / call-graph context)
    c3_taint  + the taint path found by the static engine, when one exists   (an extra column, not part of C3)
All three use the same token budget, so differences come from the information, not from length.
"""
import argparse
import json
from pathlib import Path

from analysis_engine.baselines.common import SCOPE_CWES
from analysis_engine.context.builder import ALL_SECTIONS, build_context, estimate_tokens
from analysis_engine.graph.callgraph import MODULE_NODE
from analysis_engine.project import Project
from analysis_engine.security.aliases import build_alias_map, canonical_name
from analysis_engine.security.rule_loader import load_taint_rules
from analysis_engine.security.taint import _name_matches, find_taint_flows

C2_SECTIONS = ("target",)
C3_SECTIONS = ("target", "callsites", "callees", "imports")


def candidates(project: Project, rules=None) -> list:
    """(path, qualified_name) of every function (or "" for top-level code) that calls a dangerous API."""
    rules = rules or load_taint_rules()
    out = []
    for path, f in sorted(project.file_map.items()):
        lang_rules = rules.languages.get(f.language)
        if lang_rules is None:
            continue
        patterns = [m for cwe, specs in lang_rules.sinks.items() if cwe in SCOPE_CWES for s in specs for m in s.match]
        aliases = build_alias_map(f)
        hit = lambda calls: any(  # noqa: E731
            _name_matches(patterns, c.name, canonical_name(c.name, aliases)) for c in calls)
        out += [(path, fn.qualified_name) for fn in f.functions if hit(fn.calls)]
        if hit(f.module_calls):
            out.append((path, ""))
    return out


def _entry(project, target, flow, budget, sections):
    pkg = build_context(project, target, flow, budget, sections=sections)
    return {"context_text": pkg.token_trimmed_context, "tokens": estimate_tokens(pkg.token_trimmed_context),
            "callers": pkg.callers, "callees": pkg.callees, "imports": pkg.imports, "taint_path": pkg.taint_path}


def build_ablation_inputs(project: Project, budget_tokens: int = 2000) -> list:
    flows = {}
    for flow in find_taint_flows(project):
        flows.setdefault(flow.sink_unit, flow)
    items = []
    for path, qn in candidates(project):
        target = f"{path}::{qn or MODULE_NODE}"
        info = next((fn for fn in project.file_map[path].functions if fn.qualified_name == qn), None)
        flow = flows.get((path, qn))
        c3t = _entry(project, target, flow, budget_tokens, ALL_SECTIONS)
        c3t["available"] = flow is not None
        c3t["kind"] = None if flow is None else ("entry-point parameter" if flow.entry_param else "untrusted source")
        items.append({
            "item_id": target, "file": path, "function": qn or None, "language": project.file_map[path].language,
            "start_line": info.start_line if info else None, "end_line": info.end_line if info else None,
            "c2": _entry(project, target, None, budget_tokens, C2_SECTIONS),
            "c3": _entry(project, target, None, budget_tokens, C3_SECTIONS), "c3_taint": c3t})
    return items


def summarize(items: list) -> dict:
    n = len(items) or 1
    return {"items": len(items),
            "mean_tokens": {k: round(sum(i[k]["tokens"] for i in items) / n, 1) for k in ("c2", "c3", "c3_taint")},
            "items_with_taint_path": sum(1 for i in items if i["c3_taint"]["available"]),
            "items_with_callers": sum(1 for i in items if i["c3"]["callers"]),
            "items_with_callees": sum(1 for i in items if i["c3"]["callees"])}


def main() -> None:
    ap = argparse.ArgumentParser(description="Build C2/C3 ablation inputs")
    ap.add_argument("folder")
    ap.add_argument("--out", default="ablation_inputs.jsonl")
    ap.add_argument("--budget", type=int, default=2000)
    args = ap.parse_args()
    items = build_ablation_inputs(Project.from_root(Path(args.folder)), args.budget)
    Path(args.out).write_text("".join(json.dumps(i) + "\n" for i in items), encoding="utf-8")
    print(json.dumps(summarize(items), indent=2))


if __name__ == "__main__":
    main()
