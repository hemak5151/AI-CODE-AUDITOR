"""Re-create the Member 1 results from a clean clone with one command.

    python -m analysis_engine.reproduce --out repro_out [--tools ours,bandit,semgrep] [--tests] [--repos]

Always: records the environment (Python, OS, git commit, tool versions, Semgrep rules commit), scores the labelled
development set and compares the counts with the values reported in the paper. A tool that is not installed is SKIPPED,
a count that differs is a FAIL (the exit code is then 1). Optional: --tests runs the unit tests; --repos clones `click`
and times the whole pipeline on it (informational: sizes and times depend on the machine and the repo version).
"""
import argparse
import json
import platform
import subprocess
import sys
import time
from pathlib import Path

from analysis_engine.baselines.common import SEMGREP_RULES_COMMIT, find_tool, tool_version
from analysis_engine.static_eval import evaluate

# Strict-mode counts reported in the paper (pinned tool versions and rules commit).
EXPECTED = {"cases": 68, "vulnerable": 37,
            "ours_proven": {"tp": 36, "fp": 2, "fn": 1, "tn": 29},
            "bandit": {"tp": 15, "fp": 11, "fn": 22, "tn": 20},
            "semgrep": {"tp": 29, "fp": 9, "fn": 8, "tn": 22}}


def _git(args: list, cwd=None) -> str:
    try:
        r = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, timeout=120)
        return r.stdout.strip() if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def environment(tools: set) -> dict:
    env: dict = {"python": sys.version.split()[0], "platform": platform.platform(),
           "git_commit": _git(["rev-parse", "HEAD"], Path(__file__).parent) or None, "semgrep_rules_commit": SEMGREP_RULES_COMMIT}
    for t in ("bandit", "semgrep"):
        cmd = find_tool(t)
        env[t] = tool_version(cmd) if cmd else None
    return env


def run(out: Path, tools: set, run_tests: bool = False, repos: bool = False, rules_dir=None) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    env = environment(tools)
    usable = {t for t in tools if t == "ours" or env.get(t)}
    cases, results = evaluate(out / "static_eval", usable, rules_dir)
    checks = {"cases": "PASS" if (len(cases), sum(c.vulnerable for c in cases)) == (EXPECTED["cases"], EXPECTED["vulnerable"]) else "FAIL"}
    for key, tool in (("ours_proven", "ours_proven"), ("bandit", "bandit"), ("semgrep", "semgrep")):
        if tool not in results:
            checks[key] = "SKIP (not run)"
            continue
        s = results[tool]["strict"]
        got = {k: s[k] for k in ("tp", "fp", "fn", "tn")}
        checks[key] = "PASS" if got == EXPECTED[key] else f"FAIL (got {got}, paper {EXPECTED[key]})"
    report: dict = {"environment": env, "checks": checks}
    if run_tests:
        r = subprocess.run([sys.executable, "-m", "pytest", "analysis_engine/tests", "-q"], capture_output=True, text=True)
        last = (r.stdout.strip().splitlines() or [""])[-1]
        report["unit_tests"] = last
        checks["unit_tests"] = "PASS" if r.returncode == 0 else "FAIL"
    if repos:
        from analysis_engine.pipeline import analyze_repo
        dest = out / "repos" / "click"
        if not dest.exists():
            subprocess.run(["git", "clone", "-q", "--depth", "1", "https://github.com/pallets/click", str(dest)], check=False)
        if dest.exists():
            t0 = time.perf_counter()
            stats = analyze_repo(dest).stats
            report["click"] = {"commit": _git(["rev-parse", "HEAD"], dest), "wall_seconds": round(time.perf_counter() - t0, 2), **{k: stats[k] for k in ("files", "lines_of_code", "findings", "findings_by_cwe")}}
    report["ok"] = not any(v.startswith("FAIL") for v in checks.values())
    (out / "repro_results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = ["# Reproduction report\n", "```", json.dumps(env, indent=2), "```\n", "| check | result |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in checks.items()]
    (out / "repro_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Reproduce the Member 1 results")
    ap.add_argument("--out", default="repro_out")
    ap.add_argument("--tools", default="ours,bandit,semgrep")
    ap.add_argument("--tests", action="store_true")
    ap.add_argument("--repos", action="store_true")
    ap.add_argument("--rules-dir")
    a = ap.parse_args()
    rep = run(Path(a.out), {t.strip() for t in a.tools.split(",")}, a.tests, a.repos, a.rules_dir)
    print(json.dumps(rep["environment"], indent=1))
    for k, v in rep["checks"].items():
        print(f"{k:<12} {v}")
    print("RESULT:", "OK" if rep["ok"] else "MISMATCH (see above)")
    sys.exit(0 if rep["ok"] else 1)


if __name__ == "__main__":
    main()
