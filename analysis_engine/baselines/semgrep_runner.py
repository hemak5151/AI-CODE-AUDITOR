"""Semgrep (Python + JavaScript) with a pinned rule set: fetch rules, run, convert JSON to Findings."""
import json
import subprocess
from pathlib import Path
from typing import Optional

from analysis_engine.baselines.common import (CONFIDENCE, DEFAULT_CONFIDENCE, SEMGREP_RULES_COMMIT, SEMGREP_RULES_URL,
                                              SEVERITY, cache_dir, find_tool, make_finding, parse_cwes, rel_path,
                                              run_command, sort_findings, tool_env, tool_version)


def _git(args: list, cwd: Path) -> str:
    proc = subprocess.run(["git"] + args, cwd=str(cwd), env=tool_env(), capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()[-300:]}")
    return proc.stdout.strip()


def fetch_semgrep_rules(dest_parent: Optional[Path] = None, commit: str = SEMGREP_RULES_COMMIT) -> Path:
    """Download the pinned semgrep-rules commit (once) and return the folder.

    The folder must be named `semgrep-rules`: Semgrep builds rule ids from the path, and we strip the part
    before it. The rules are NOT redistributable (Semgrep Rules License v1.0), so they live outside the repo.
    """
    parent = Path(dest_parent) if dest_parent else cache_dir()
    dest = parent / "semgrep-rules"
    if (dest / ".git").exists() and _git(["rev-parse", "HEAD"], dest) == commit:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        _git(["init", "-q"], dest)
        _git(["remote", "add", "origin", SEMGREP_RULES_URL], dest)
    _git(["fetch", "--depth", "1", "origin", commit], dest)
    _git(["checkout", "-q", "FETCH_HEAD"], dest)
    head = _git(["rev-parse", "HEAD"], dest)
    if head != commit:
        raise RuntimeError(f"semgrep-rules is at {head}, expected {commit}")
    return dest


def rules_commit(rules_dir: Path) -> Optional[str]:
    try:
        return _git(["rev-parse", "HEAD"], Path(rules_dir))
    except (RuntimeError, OSError):
        return None


def short_rule_id(check_id: str) -> str:
    """'Users.hp.cache.semgrep-rules.python.flask.security.x' -> 'python.flask.security.x'"""
    return check_id.split("semgrep-rules.", 1)[-1]


def normalize_semgrep(raw: dict, stage: Path) -> list:
    findings = {}
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata") or {}
        cwes = parse_cwes(meta.get("cwe"))
        category = meta.get("category")
        if category not in (None, "security") and not cwes:
            continue  # best-practice / correctness / performance rules are not security findings
        rule = short_rule_id(r["check_id"])
        message = " ".join(str(extra.get("message", "")).split())
        first = message.split(". ")[0].rstrip(".") + "." if message else rule
        also = f" Also tagged: {', '.join(cwes[1:])}." if len(cwes) > 1 else ""
        file = rel_path(r["path"], stage)
        f = make_finding("semgrep", rule, cwes[0] if cwes else None, SEVERITY.get(extra.get("severity"), "low"),
                         CONFIDENCE.get(str(meta.get("confidence", "")).upper(), DEFAULT_CONFIDENCE), first,
                         f"{message}{also}", file, r["start"]["line"], r["end"]["line"], stage)
        findings.setdefault(f.finding_id, f)
    return sort_findings(list(findings.values()))


def run_semgrep(stage: Path, work: Path, rules_dir: Path, rule_dirs=("python", "javascript"), repeat: int = 1,
                jobs: int = 1) -> dict:
    prefix = find_tool("semgrep")
    if prefix is None:
        return {"available": False, "errors": ["semgrep is not installed (pip install semgrep)"]}
    out_json = work / "semgrep_raw.json"
    cmd = prefix + ["scan"]
    for d in rule_dirs:
        cmd += ["--config", str(Path(rules_dir) / d)]
    cmd += ["--metrics=off", "--disable-version-check", "--no-git-ignore", "--json", "--quiet", "--time",
            "--jobs", str(jobs), "-o", str(out_json), str(stage)]
    runs, errors, code, raw = [], [], 0, None
    for _ in range(max(repeat, 1)):
        code, _stdout, stderr, seconds = run_command(cmd)
        if code not in (0, 1) or not out_json.exists():
            errors.append(f"semgrep exited with {code}: {stderr.strip()[-500:]}")
            break
        raw = json.loads(out_json.read_text(encoding="utf-8"))
        prof = (raw.get("time") or {}).get("profiling_times") or {}
        runs.append({"seconds_total": round(seconds, 3),
                     "seconds_rule_loading": round(prof["config_time"], 3) if "config_time" in prof else None,
                     "seconds_scan": round(prof["core_time"], 3) if "core_time" in prof else None})
    scan_errors = [e.get("message", str(e))[:300] for e in (raw or {}).get("errors", [])]
    return {"available": True, "version": tool_version(prefix), "command": cmd, "raw": raw, "runs": runs,
            "returncode": code, "errors": errors + scan_errors,
            "findings": normalize_semgrep(raw, stage) if raw else []}
