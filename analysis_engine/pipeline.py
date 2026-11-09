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
from analysis_engine.security.patterns import find_risky_patterns
from analysis_engine.security.rule_loader import load_taint_rules
from analysis_engine.security.secrets import find_hardcoded_secrets
from analysis_engine.security.taint import TaintAnalyzer, flow_to_finding
from shared.schemas import ContextPackage, Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class RepoAnalysis:
    findings: list = field(default_factory=list)
    smells: list = field(default_factory=list)
    metrics: list = field(default_factory=list)
    contexts: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)


class AnalysisSession:
    """A repo analysed once and kept up to date as files change.

        session = AnalysisSession(Project.from_root("repo"))
        first = session.analyze()                         # full analysis
        after = session.update_file("db.py", new_code)    # only db.py and what depends on it are redone
        session.findings_for("db.py")                     # findings in one file, from the latest result

    `update_file(path, None)` removes a file. Updating returns the same RepoAnalysis as a full run would
    (the tests check this), so a patch can be validated by comparing findings before and after.
    """

    def __init__(self, project: Project, budget_tokens: int = 2000, entry_point_params: bool = True,
                 entry_point_methods: bool = False, progress=None, include_tests: bool = False):
        self.project = project
        self.include_tests = include_tests  # also report name-based secrets found in tests/ and examples/
        self.progress = progress  # progress(stage, done, total); stages: parse, scan, taint
        self.budget_tokens = budget_tokens
        self.rules = load_taint_rules()
        self.entry_point_params = entry_point_params
        self.entry_point_methods = entry_point_methods
        self._taint: Optional[TaintAnalyzer] = None
        self._flows: list = []
        self._per_file: dict = {}  # path -> (findings, metrics) from the pattern-based detectors
        self.result: Optional[RepoAnalysis] = None

    def _scan_file(self, path: str) -> None:
        """Everything that looks at one file on its own, in one pass over one parse tree."""
        findings = (find_hardcoded_secrets(self.project, self.rules, [path], self.include_tests)
                    + find_deprecated_apis(self.project, None, [path])
                    + find_risky_patterns(self.project, self.rules, [path]))
        self._per_file[path] = (findings, compute_metrics(self.project, None, [path]))

    def analyze(self) -> "RepoAnalysis":
        started = time.perf_counter()
        self._per_file = {}
        paths = sorted(self.project.file_map)
        for i, path in enumerate(paths, 1):
            self._scan_file(path)
            if self.progress:
                self.progress("scan", i, len(paths))
        self._taint = TaintAnalyzer(self.project, self.rules, self.entry_point_params, self.entry_point_methods,
                                    self.progress)
        self._flows = self._taint.run()
        return self._assemble(started, incremental=False)

    def update_file(self, path: str, source: Optional[str]) -> "RepoAnalysis":
        if self._taint is None:
            raise RuntimeError("call analyze() before update_file()")
        started = time.perf_counter()
        before = self._taint.seeds_for_paths({path})  # callers, per the call graph as it is now
        self.project.update_source(path, source)
        self._per_file.pop(path, None)
        if path in self.project.file_map:
            self._scan_file(path)
        self._flows = self._taint.update({path}, before)
        return self._assemble(started, incremental=True)

    def findings_for(self, path: str) -> list:
        return [f for f in (self.result.findings if self.result else []) if f.file_path == path]

    def _assemble(self, started: float, incremental: bool) -> "RepoAnalysis":
        project = self.project
        findings: dict = {}
        contexts: dict = {}
        for flow in self._flows:
            finding = flow_to_finding(flow, self.rules, project)
            findings.setdefault(finding.finding_id, finding)
            path, qn = flow.sink_unit
            target = f"{path}::{qn or MODULE_NODE}"
            contexts.setdefault(finding.finding_id, build_context(project, target, flow, self.budget_tokens))
        metrics: list = []
        proven = {(f.cwe_id, f.file_path, f.line_number) for f in findings.values()}
        for path in sorted(self._per_file):
            file_findings, file_metrics = self._per_file[path]
            metrics += file_metrics
            for finding in file_findings:
                if finding.source == "pattern-rule" and (finding.cwe_id, finding.file_path, finding.line_number) in proven:
                    continue  # a proven data flow on this line replaces the pattern-level finding
                if finding.finding_id not in findings:
                    findings[finding.finding_id] = finding
                    target = target_for_line(project, finding.file_path, finding.line_number)
                    contexts[finding.finding_id] = build_context(project, target, None, self.budget_tokens)
        ordered = sorted(findings.values(), key=lambda f: (SEVERITY_ORDER[f.severity.value], f.file_path,
                                                           f.line_number, f.finding_id))
        loc = sum(len(project.lines(p)) for p in project.sources)
        seconds = time.perf_counter() - started
        by_cwe: dict = {}
        for f in ordered:
            by_cwe[f.cwe_id] = by_cwe.get(f.cwe_id, 0) + 1
        stats = {
            "files": len(project.files), "lines_of_code": loc, "functions": len(metrics),
            "findings": len(ordered), "findings_by_cwe": dict(sorted(by_cwe.items(), key=lambda kv: str(kv[0]))),
            "taint_findings": sum(1 for f in ordered if f.source == "taint-engine"),
            "entry_point_findings": sum(1 for f in ordered if f.source == "taint-engine-entry"),
            "smells": sum(len(m.smells) for m in metrics), "incremental": incremental,
            "seconds": round(seconds, 3),
            "seconds_per_1000_loc": round(seconds / (loc / 1000), 3) if loc and not incremental else None,
        }
        self.result = RepoAnalysis(ordered, smell_findings(metrics), metrics, contexts, stats)
        return self.result


def analyze_project(project: Project, budget_tokens: int = 2000, entry_point_params: bool = True,
                    entry_point_methods: bool = False, include_tests: bool = False) -> RepoAnalysis:
    return AnalysisSession(project, budget_tokens, entry_point_params, entry_point_methods,
                           include_tests=include_tests).analyze()


def analyze_sources(sources: dict, budget_tokens: int = 2000, entry_point_params: bool = True,
                    entry_point_methods: bool = False, include_tests: bool = False) -> RepoAnalysis:
    return analyze_project(Project.from_sources(sources), budget_tokens, entry_point_params, entry_point_methods,
                           include_tests)


def analyze_repo(root, budget_tokens: int = 2000, entry_point_params: bool = True,
                 entry_point_methods: bool = False, include_tests: bool = False) -> RepoAnalysis:
    return analyze_project(Project.from_root(root), budget_tokens, entry_point_params, entry_point_methods,
                           include_tests)


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
    ap.add_argument("--include-tests", action="store_true",
                    help="also report hardcoded credentials found in tests/ and examples/ folders")
    ap.add_argument("--entry-methods", action="store_true",
                    help="also treat parameters of uncalled class methods as outside input (noisy in libraries)")
    args = ap.parse_args()
    if args.target.endswith(".zip"):
        root = from_zip(args.target)
    elif args.target.startswith(("http://", "https://", "git@")):
        root = from_git(args.target)
    else:
        root = Path(args.target)
    result = analyze_repo(root, args.budget, not args.no_entry_params, args.entry_methods, args.include_tests)
    write_outputs(result, args.out)
    print(json.dumps(result.stats, indent=2))
    for f in result.findings[:15]:
        print(f"[{f.severity.value:>8}] {f.cwe_id} {f.file_path}:{f.line_number}  {f.message}  (conf {f.confidence})")
    if len(result.findings) > 15:
        print(f"... and {len(result.findings) - 15} more. Full list in {args.out}/findings.json")


if __name__ == "__main__":
    main()
