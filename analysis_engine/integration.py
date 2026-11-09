"""One call for the backend: analyse an extracted repo and return what a job needs to store.

    from analysis_engine.integration import analyze_job
    result = analyze_job(root, progress)       # root: folder of the extracted upload / clone
    result.findings    list of Finding dicts (JSON-ready, shared schema), most severe first
    result.sources     {relative path: file text} for every file a finding refers to, so the UI can show it
    result.contexts    {finding_id: ContextPackage dict}
    result.files_scanned

`progress(stage, done, total)` is called while it works. Stages, in order: "parse", "scan", "taint".
It is safe to run several jobs in different threads at the same time.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from analysis_engine.pipeline import AnalysisSession
from analysis_engine.project import Project

ProgressFn = Callable[[str, int, int], None]
EVIDENCE_FILE = re.compile(r"\[([^\]\[]+):\d+\]")


@dataclass
class JobAnalysis:
    findings: list = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    contexts: dict = field(default_factory=dict)
    smells: list = field(default_factory=list)
    files_scanned: int = 0
    stats: dict = field(default_factory=dict)


def analyze_job(root, progress: Optional[ProgressFn] = None, budget_tokens: int = 2000,
                entry_point_params: bool = True, include_tests: bool = False) -> JobAnalysis:
    project = Project.from_root(Path(root), progress)
    result = AnalysisSession(project, budget_tokens, entry_point_params, progress=progress,
                              include_tests=include_tests).analyze()
    sources: dict = {}
    for finding in result.findings:
        referenced = {finding.file_path}
        referenced.update(EVIDENCE_FILE.findall(finding.evidence or ""))  # files along a taint path
        for path in referenced:
            if path in project.sources:
                sources[path] = project.sources[path]
    return JobAnalysis(
        findings=[f.model_dump(mode="json") for f in result.findings], sources=sources,
        contexts={k: v.model_dump(mode="json") for k, v in result.contexts.items()},
        smells=[f.model_dump(mode="json") for f in result.smells], files_scanned=len(project.files),
        stats=result.stats)
