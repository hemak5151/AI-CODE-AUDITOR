"""One call that runs the whole deterministic analysis and returns Findings + context packages.

    from analysis_engine.pipeline import analyze_repo, analyze_sources
    result = analyze_repo("path/to/repo")                       # a folder
    result = analyze_sources({"a.py": "...", "b.js": "..."})    # in-memory code (snippets, benchmark items)
    result.findings   -> list[Finding]            taint flows, hardcoded secrets, deprecated APIs
    result.contexts   -> {finding_id: ContextPackage}
    result.smells     -> list[Finding]            complexity / code-smell findings (no CWE)
    result.metrics    -> list[FunctionMetrics]
    result.stats      -> counts and runtime per 1,000 lines

Command line:
    python -m analysis_engine.pipeline <folder | repo.zip | git-url> --out analysis_out [--budget 2000]
"""
import argparse
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from analysis_engine.context.builder import build_context, target_for_line
from analysis_engine.graph.callgraph import MODULE_NODE
from analysis_engine.ingest import from_git, from_zip
from analysis_engine.metrics import FunctionMetrics, compute_metrics, smell_findings
from analysis_engine.project import Project
from analysis_engine.security.deprecated import find_deprecated_apis
from analysis_engine.security.rule_loader import load_taint_rules
from analysis_engine.security.secrets import find_hardcoded_secrets
from analysis_engine.security.taint import find_taint_flows, flow_to_finding
from shared.schemas import ContextPackage, Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class RepoAnalysis:
    findings: list = field(default_factory=list)
    smells: list = field(default_factory=list)
    metrics: list = field(default_factory=list)
    contexts: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)


def analyze_project(project: Project, budget_tokens: int = 2000, entry_point_params: bool = True) -> RepoAnalysis:
    started = time.perf_counter()
    rules = load_taint_rules()
    findings: dict = {}
    contexts: dict = {}

    for flow in find_taint_flows(project, rules, entry_point_params):
        finding = flow_to_finding(flow, rules, project)
        findings.setdefault(finding.finding_id, finding)
        path, qn = flow.sink_unit
        target = f"{path}::{qn or MODULE_NODE}"
        contexts.setdefault(finding.finding_id, build_context(project, target, flow, budget_tokens))
    for finding in find_hardcoded_secrets(project, rules) + find_deprecated_apis(project):
        if finding.finding_id not in findings:
            findings[finding.finding_id] = finding
            target = target_for_line(project, finding.file_path, finding.line_number)
            contexts[finding.finding_id] = build_context(project, target, None, budget_tokens)

    metrics = compute_metrics(project)
    ordered = sorted(findings.values(), key=lambda f: (SEVERITY_ORDER[f.severity.value], f.file_path, f.line_number, f.finding_id))
    loc = sum(len(project.lines(p)) for p in project.sources)
    seconds = time.perf_counter() - started
    by_cwe: dict = {}
    for f in ordered:
        by_cwe[f.cwe_id] = by_cwe.get(f.cwe_id, 0) + 1
    stats = {
        "files": len(project.files), "lines_of_code": loc, "functions": len(metrics),
        "findings": len(ordered), "findings_by_cwe": dict(sorted(by_cwe.items())),
        "taint_findings": sum(1 for f in ordered if f.source == "taint-engine"),
        "entry_point_findings": sum(1 for f in ordered if f.source == "taint-engine-entry"),
        "smells": sum(len(m.smells) for m in metrics),
        "seconds": round(seconds, 3), "seconds_per_1000_loc": round(seconds / (loc / 1000), 3) if loc else None,
    }
    return RepoAnalysis(ordered, smell_findings(metrics), metrics, contexts, stats)


def analyze_sources(sources: dict, budget_tokens: int = 2000, entry_point_params: bool = True) -> RepoAnalysis:
    return analyze_project(Project.from_sources(sources), budget_tokens, entry_point_params)


def analyze_repo(root, budget_tokens: int = 2000, entry_point_params: bool = True) -> RepoAnalysis:
    return analyze_project(Project.from_root(root), budget_tokens, entry_point_params)


def write_outputs(result: RepoAnalysis, out_dir: str) -> list:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    payloads = {
        "findings.json": [f.model_dump(mode="json") for f in result.findings],
        "contexts.json": {k: v.model_dump(mode="json") for k, v in result.contexts.items()},
        "smells.json": [f.model_dump(mode="json") for f in result.smells],
        "metrics.json": [m.model_dump(mode="json") for m in result.metrics],
        "summary.json": result.stats,
    }
    written = []
    for name, payload in payloads.items():
        (out / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        written.append(str(out / name))
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description="Run taint, secret, deprecated-API and metrics analysis on a repo")
    ap.add_argument("target", help="folder, .zip file, or git URL")
    ap.add_argument("--out", default="analysis_out")
    ap.add_argument("--budget", type=int, default=2000, help="token budget per context package")
    ap.add_argument("--no-entry-params", action="store_true",
                    help="do not treat parameters of uncalled functions as outside input")
    args = ap.parse_args()
    if args.target.endswith(".zip"):
        root = from_zip(args.target)
    elif args.target.startswith(("http://", "https://", "git@")):
        root = from_git(args.target)
    else:
        root = Path(args.target)
    result = analyze_repo(root, args.budget, not args.no_entry_params)
    write_outputs(result, args.out)
    print(json.dumps(result.stats, indent=2))
    for f in result.findings[:15]:
        print(f"[{f.severity.value:>8}] {f.cwe_id} {f.file_path}:{f.line_number}  {f.message}  (conf {f.confidence})")
    if len(result.findings) > 15:
        print(f"... and {len(result.findings) - 15} more. Full list in {args.out}/findings.json")


if __name__ == "__main__":
    main()
