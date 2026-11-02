"""Run the C1 baselines (Bandit + Semgrep) and write result files for the evaluation harness.

    python -m analysis_engine.baselines <folder | repo.zip | git-url> --out baseline_out

Outputs (in --out):
    c1_findings.jsonl     one shared `Finding` per line, both tools ("source" says which)
    baseline_meta.json    tool versions, rules commit, commands, files scanned, lines of code, timings
    run_log.json          one shared `RunLog` per tool (model = tool+version, prompt_version = rules version)
    bandit_raw.json, semgrep_raw.json   the tools' own output, for traceability
"""
import argparse
import json
import platform
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from analysis_engine.baselines.bandit_runner import run_bandit
from analysis_engine.baselines.common import SCOPE_CWES, SEMGREP_RULES_COMMIT, median, stage_files
from analysis_engine.baselines.semgrep_runner import fetch_semgrep_rules, rules_commit, run_semgrep
from analysis_engine.ingest import cleanup, from_git, from_zip
from shared.schemas import RunLog


def _repo_commit() -> Optional[str]:
    import subprocess
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(Path(__file__).parent), capture_output=True,
                             text=True, timeout=10)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _tool_summary(result: dict, loc: int, files: int, in_scope: int) -> dict:
    runs = result.get("runs", [])
    total = median([r["seconds_total"] for r in runs])
    scan = median([r["seconds_scan"] for r in runs])
    loading = median([r["seconds_rule_loading"] for r in runs])
    per_k = lambda s: round(s / (loc / 1000), 3) if s is not None and loc else None  # noqa: E731
    return {"available": True, "version": result["version"], "command": [str(c) for c in result["command"]],
            "returncode": result["returncode"], "errors": result["errors"], "files_scanned": files,
            "lines_scanned": loc, "findings_total": len(result["findings"]), "findings_in_scope": in_scope,
            "runs": runs, "median_seconds_total": total, "median_seconds_rule_loading": loading,
            "median_seconds_scan": scan, "seconds_per_1000_loc_total": per_k(total),
            "seconds_per_1000_loc_scan": per_k(scan)}


def run_baselines(target: str, out_dir: str, tools=("bandit", "semgrep"), rules_dir: Optional[str] = None,
                  rule_dirs=("python", "javascript"), repeat: int = 1, jobs: int = 1, cwes=None) -> dict:
    cleanup_after = None
    if target.endswith(".zip"):
        root = cleanup_after = from_zip(target)
    elif target.startswith(("http://", "https://", "git@")):
        root = cleanup_after = from_git(target)
    else:
        root = Path(target)

    work = Path(tempfile.mkdtemp(prefix="baselines_"))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        stage = work / "scan"
        staged = stage_files(root, stage)
        py_loc = sum(s.lines for s in staged if s.language == "python")
        all_loc = sum(s.lines for s in staged)
        py_files = sum(1 for s in staged if s.language == "python")
        scope = set(cwes) if cwes else None
        findings, summaries = [], {}
        meta = {"configuration": "C1", "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "target": str(target), "python": sys.version.split()[0], "platform": platform.platform(),
                "scope_cwes": list(SCOPE_CWES), "filtered_to": sorted(scope) if scope else None,
                "files": [s.path for s in staged], "files_by_language": {
                    "python": py_files, "javascript": len(staged) - py_files},
                "lines_by_language": {"python": py_loc, "javascript": all_loc - py_loc}}

        def keep(fs: list) -> list:
            return [f for f in fs if f.cwe_id in scope] if scope else fs

        def count_scope(fs: list) -> int:
            return sum(1 for f in fs if f.cwe_id in SCOPE_CWES)

        if "bandit" in tools:
            res = run_bandit(stage, work, repeat)
            if res["available"]:
                kept = keep(res["findings"])
                findings += kept
                summaries["bandit"] = _tool_summary({**res, "findings": kept}, py_loc, py_files, count_scope(kept))
                if res["raw"] is not None:
                    shutil.copyfile(work / "bandit_raw.json", out / "bandit_raw.json")
            else:
                summaries["bandit"] = {"available": False, "errors": res["errors"]}
        if "semgrep" in tools:
            try:
                rules = Path(rules_dir) if rules_dir else fetch_semgrep_rules()
                res = run_semgrep(stage, work, rules, rule_dirs, repeat, jobs)
            except RuntimeError as exc:
                res = {"available": False, "errors": [str(exc)]}
            if res["available"]:
                kept = keep(res["findings"])
                findings += kept
                summaries["semgrep"] = _tool_summary({**res, "findings": kept}, all_loc, len(staged), count_scope(kept))
                summaries["semgrep"]["rules_commit"] = rules_commit(rules)
                summaries["semgrep"]["rules_commit_pinned"] = SEMGREP_RULES_COMMIT
                summaries["semgrep"]["rule_dirs"] = list(rule_dirs)
                if res["raw"] is not None:
                    shutil.copyfile(work / "semgrep_raw.json", out / "semgrep_raw.json")
            else:
                summaries["semgrep"] = {"available": False, "errors": res["errors"]}

        findings.sort(key=lambda f: (f.file_path, f.line_number, f.source, f.finding_id))
        meta["tools"] = summaries
        meta["findings_total"] = len(findings)
        meta["findings_by_cwe"] = dict(sorted(
            {c: sum(1 for f in findings if f.cwe_id == c) for c in {f.cwe_id for f in findings}}.items(),
            key=lambda kv: str(kv[0])))

        run_logs = []
        for name, s in summaries.items():
            if not s.get("available"):
                continue
            run_logs.append(RunLog(
                model=f"{name} {s['version']}",
                prompt_version=f"rules@{(s.get('rules_commit') or '')[:8]}" if name == "semgrep" else "builtin",
                seed=None, tokens=None,
                latency_ms=round((s["median_seconds_total"] or 0) * 1000, 1),
                commit_hash=_repo_commit(), date=meta["date"]))

        (out / "c1_findings.jsonl").write_text(
            "".join(json.dumps(f.model_dump(mode="json")) + "\n" for f in findings), encoding="utf-8")
        (out / "baseline_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        (out / "run_log.json").write_text(json.dumps([r.model_dump(mode="json") for r in run_logs], indent=2),
                                          encoding="utf-8")
        return meta
    finally:
        shutil.rmtree(work, ignore_errors=True)
        if cleanup_after is not None:
            cleanup(cleanup_after)


def _parse_cwes(text: str):
    if text == "all":
        return None
    if text == "scope":
        return list(SCOPE_CWES)
    return [c.strip() if c.strip().startswith("CWE-") else f"CWE-{c.strip()}" for c in text.split(",") if c.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the C1 baselines (Bandit + Semgrep)")
    ap.add_argument("target", help="folder, .zip file, or git URL")
    ap.add_argument("--out", default="baseline_out")
    ap.add_argument("--tools", default="bandit,semgrep")
    ap.add_argument("--rules-dir", help="existing semgrep-rules clone (default: download the pinned commit)")
    ap.add_argument("--rule-dirs", default="python,javascript", help="rule folders inside semgrep-rules")
    ap.add_argument("--repeat", type=int, default=1, help="repeat each tool N times; the median time is reported")
    ap.add_argument("--jobs", type=int, default=1, help="Semgrep worker processes (1 keeps timing comparable)")
    ap.add_argument("--cwes", default="all", help="'all', 'scope', or a list like 89,78,22")
    args = ap.parse_args()
    meta = run_baselines(args.target, args.out, tuple(t.strip() for t in args.tools.split(",") if t.strip()),
                         args.rules_dir, tuple(args.rule_dirs.split(",")), args.repeat, args.jobs, _parse_cwes(args.cwes))
    print(f"Scanned {len(meta['files'])} files ({meta['lines_by_language']['python']} Python lines, "
          f"{meta['lines_by_language']['javascript']} JavaScript lines)\n")
    print(f"{'tool':<8} {'version':<9} {'findings':>8} {'in scope':>9} {'total s':>9} {'rule load s':>12} "
          f"{'scan s':>8} {'scan s/1000 LOC':>16}")
    for name, s in meta["tools"].items():
        if not s.get("available"):
            print(f"{name:<8} NOT RUN: {'; '.join(s['errors'])}")
            continue
        show = lambda v: "-" if v is None else f"{v:.2f}"  # noqa: E731
        print(f"{name:<8} {s['version']:<9} {s['findings_total']:>8} {s['findings_in_scope']:>9} "
              f"{show(s['median_seconds_total']):>9} {show(s['median_seconds_rule_loading']):>12} "
              f"{show(s['median_seconds_scan']):>8} {show(s['seconds_per_1000_loc_scan']):>16}")
        for e in s["errors"][:3]:
            print(f"   warning: {e}")
    print(f"\nWritten to {args.out}/ (c1_findings.jsonl, baseline_meta.json, run_log.json)")


if __name__ == "__main__":
    main()
