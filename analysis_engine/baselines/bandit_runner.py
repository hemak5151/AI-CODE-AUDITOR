"""Bandit (Python only): run it and convert its JSON to shared Finding objects."""
import json
from pathlib import Path
from typing import Optional

from analysis_engine.baselines.common import (CONFIDENCE, DEFAULT_CONFIDENCE, SEVERITY, find_tool, make_finding,
                                              parse_cwes, rel_path, run_command, sort_findings, tool_version)


def normalize_bandit(raw: dict, stage: Path) -> list:
    findings = {}
    for r in raw.get("results", []):
        file = rel_path(r["filename"], stage)
        cwes = parse_cwes((r.get("issue_cwe") or {}).get("id"))
        lines = r.get("line_range") or [r["line_number"]]
        test_id = r["test_id"]
        text = r["issue_text"]
        explanation = f"{text} (Bandit test {test_id}: {r.get('test_name', '')}). {r.get('more_info', '')}".strip()
        f = make_finding("bandit", test_id, cwes[0] if cwes else None, SEVERITY.get(r["issue_severity"], "low"),
                         CONFIDENCE.get(r["issue_confidence"], DEFAULT_CONFIDENCE), text, explanation, file,
                         r["line_number"], max(lines), stage)
        f.line_range.start = min(min(lines), r["line_number"])
        findings.setdefault(f.finding_id, f)
    return sort_findings(list(findings.values()))


def run_bandit(stage: Path, work: Path, repeat: int = 1) -> dict:
    """Returns {"available", "version", "command", "raw", "findings", "runs", "returncode", "errors"}."""
    prefix = find_tool("bandit")
    if prefix is None:
        return {"available": False, "errors": ["bandit is not installed (pip install bandit), or set BANDIT_CMD to its full path"]}
    out_json = work / "bandit_raw.json"
    cmd = prefix + ["-r", str(stage), "-f", "json", "-o", str(out_json), "-q"]
    runs, errors, code = [], [], 0
    for _ in range(max(repeat, 1)):
        code, _stdout, stderr, seconds = run_command(cmd)
        runs.append({"seconds_total": round(seconds, 3), "seconds_rule_loading": None, "seconds_scan": round(seconds, 3)})
        if code not in (0, 1) or not out_json.exists():  # Bandit exits 1 when it finds issues
            errors.append(f"bandit exited with {code}: {stderr.strip()[-500:]}")
            break
    raw: Optional[dict] = json.loads(out_json.read_text(encoding="utf-8")) if out_json.exists() and not errors else None
    return {"available": True, "version": tool_version(prefix), "command": cmd, "raw": raw, "runs": runs,
            "returncode": code, "errors": errors + [str(e) for e in (raw or {}).get("errors", [])],
            "findings": normalize_bandit(raw, stage) if raw else []}
