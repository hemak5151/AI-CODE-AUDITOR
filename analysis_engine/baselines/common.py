"""Shared helpers for the C1 baselines (Bandit and Semgrep): staging, timing, CWE parsing, Finding creation."""
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from analysis_engine.ingest import iter_source_files
from shared.schemas import Finding, LineRange, Severity

# Semgrep's rules are licensed "for internal business use only": never copy them into this repo.
# We pin the exact version by commit and download it on demand to a cache outside the repo.
SEMGREP_RULES_URL = "https://github.com/semgrep/semgrep-rules"
SEMGREP_RULES_COMMIT = "16b9e6d45f10649f6a531ec4838ed9924372c3bc"  # semgrep-rules, 2026-10-21

BASELINE_LANGUAGES = {"python", "javascript"}
SCOPE_CWES = ("CWE-89", "CWE-78", "CWE-22", "CWE-502", "CWE-798", "CWE-95")

SEVERITY = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "ERROR": "high", "WARNING": "medium", "INFO": "low"}
CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
DEFAULT_CONFIDENCE = 0.5


def cache_dir() -> Path:
    return Path(os.environ.get("AI_AUDITOR_CACHE") or Path.home() / ".cache" / "ai-code-auditor")


def tool_env() -> dict:
    env = dict(os.environ)
    env.update({"PYTHONUTF8": "1", "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "NO_COLOR": "1"})
    return env


def find_tool(name: str) -> Optional[list]:
    """Command prefix for a tool, or None.

    Order: the BANDIT_CMD / SEMGREP_CMD environment variable (lets the tools live in their own virtual
    environment, away from the backend's packages), then PATH, then `python -m <tool>`.
    """
    override = os.environ.get(f"{name.upper()}_CMD")
    if override:
        parts = [t.strip('"') for t in shlex.split(override, posix=(os.name != "nt"))]
        return parts if parts and (shutil.which(parts[0]) or os.path.exists(parts[0])) else None
    found = shutil.which(name)
    if found:
        return [found]
    import importlib.util
    if importlib.util.find_spec(name):
        return [sys.executable, "-m", name]
    return None


def run_command(cmd: list, cwd: Optional[str] = None) -> tuple:
    """Run a command; return (returncode, stdout, stderr, wall_seconds)."""
    started = time.perf_counter()
    env = tool_env()
    if os.path.isabs(cmd[0]):
        # A tool installed in its own environment must find ITS helper programs (Semgrep's launcher starts
        # `pysemgrep` from PATH), not copies from whichever environment happens to be active.
        env["PATH"] = str(Path(cmd[0]).parent) + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout, proc.stderr, time.perf_counter() - started


def tool_version(cmd_prefix: list) -> str:
    code, out, err, _ = run_command(cmd_prefix + ["--version"])
    lines = [l.strip() for l in (out + "\n" + err).splitlines() if l.strip()]
    first = next((l for l in lines if re.search(r"\d+\.\d+", l)), "unknown")
    m = re.search(r"\d+\.\d+(?:\.\d+)*", first)
    return m.group(0) if m else first


# ---------------------------------------------------------------- staging
@dataclass
class StagedFile:
    path: str      # relative, forward slashes
    language: str
    lines: int


def stage_files(root: Path, dest: Path) -> list:
    """Copy exactly the Python/JavaScript files we selected into `dest` (same relative paths).

    Both tools then scan the identical file set. Semgrep's own default ignore rules
    (which silently skip tests/ and more) are disabled by an empty .semgrepignore.
    """
    root, dest = Path(root), Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    staged = []
    for path, language in iter_source_files(root):
        if language not in BASELINE_LANGUAGES:
            continue
        rel = path.relative_to(root).as_posix()
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
        staged.append(StagedFile(rel, language, len(text.splitlines())))
    (dest / ".semgrepignore").write_text("", encoding="utf-8")
    return sorted(staged, key=lambda s: s.path)


def rel_path(raw: str, stage: Path) -> str:
    """Path as reported by a tool -> path relative to the staged root, forward slashes (Windows-safe)."""
    p = raw.replace("\\", "/")
    s = str(stage).replace("\\", "/").rstrip("/")
    if p.lower().startswith(s.lower() + "/"):
        p = p[len(s) + 1:]
    while p.startswith("./"):
        p = p[2:]
    return p


# ---------------------------------------------------------------- findings
def parse_cwes(value) -> list:
    """['CWE-78: Improper ...', 'CWE-77'] or 'CWE-78' or 78 -> ['CWE-78', 'CWE-77']"""
    if value is None:
        return []
    text = " ".join(str(v) for v in value) if isinstance(value, (list, tuple)) else str(value)
    out = []
    for n in re.findall(r"CWE-(\d+)", text) or (re.findall(r"^\d+$", text.strip()) if text.strip().isdigit() else []):
        if n != "0" and f"CWE-{n}" not in out:
            out.append(f"CWE-{n}")
    return out


def make_finding(tool: str, rule_id: str, cwe: Optional[str], severity: str, confidence: float, message: str,
                 explanation: str, file: str, line: int, end_line: int, stage: Path) -> Finding:
    lines_text = []
    try:
        lines_text = (Path(stage) / file).read_bytes().decode("utf-8-sig", errors="replace").splitlines()
    except OSError:
        pass
    evidence = lines_text[line - 1].strip()[:200] if 0 < line <= len(lines_text) else None
    digest = hashlib.sha1(f"{tool}|{rule_id}|{file}|{line}".encode()).hexdigest()[:10]
    start, end = line, max(end_line, line)
    return Finding(
        finding_id=f"{tool}-{digest}", cwe_id=cwe, severity=Severity(severity), confidence=confidence,
        message=f"[{tool} {rule_id}] {message}"[:300], explanation=explanation, file_path=file, line_number=line,
        line_range=LineRange(start=start, end=end), evidence=evidence, source=f"baseline-{tool}")


def sort_findings(findings: list) -> list:
    return sorted(findings, key=lambda f: (f.file_path, f.line_number, f.message))


def median(values: list) -> Optional[float]:
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


def dedupe_by_location(findings: list) -> list:
    """One finding per (tool, file, line, CWE). Semgrep often reports the same line from several rules;
    count a location once when computing precision/recall. The strictest severity and highest confidence win."""
    best: dict = {}
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for f in findings:
        key = (f.source, f.file_path, f.line_number, f.cwe_id)
        cur = best.get(key)
        if cur is None:
            best[key] = f.model_copy(deep=True)
        else:
            if order[f.severity.value] > order[cur.severity.value]:
                cur.severity = f.severity
            cur.confidence = max(cur.confidence, f.confidence)
    return sort_findings(list(best.values()))
