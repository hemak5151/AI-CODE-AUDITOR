import json
import os
import shutil

import pytest

from analysis_engine.baselines.bandit_runner import normalize_bandit
from analysis_engine.baselines.common import (SCOPE_CWES, dedupe_by_location, parse_cwes, rel_path, stage_files)
from analysis_engine.baselines.run import run_baselines
from analysis_engine.baselines.semgrep_runner import normalize_semgrep, short_rule_id
from shared.schemas import Finding, RunLog

APP = ("import os\nfrom flask import request\n\n\ndef cmd():\n    os.system('ping ' + request.args['h'])\n")


@pytest.fixture
def stage(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(APP)
    return tmp_path


def bandit_result(**kw):
    base = {"filename": "src/app.py", "line_number": 6, "line_range": [6], "test_id": "B605",
            "test_name": "start_process_with_a_shell", "issue_severity": "HIGH", "issue_confidence": "MEDIUM",
            "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
            "issue_text": "Starting a process with a shell, possible injection detected.",
            "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b605.html"}
    return {**base, **kw}


def semgrep_result(**kw):
    base = {"check_id": "home.me.cache.semgrep-rules.python.flask.security.injection.os-system-injection",
            "path": "{stage}/src/app.py", "start": {"line": 6, "col": 5}, "end": {"line": 6, "col": 40},
            "extra": {"message": "User data detected in os.system. You may be vulnerable to command injection.",
                      "severity": "ERROR", "lines": "requires login",
                      "metadata": {"category": "security", "confidence": "HIGH",
                                   "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"]}}}
    return {**base, **kw}


# ---------------------------------------------------------------- helpers
def test_parse_cwes():
    assert parse_cwes(["CWE-78: Improper Neutralization", "CWE-77: x", "CWE-78"]) == ["CWE-78", "CWE-77"]
    assert parse_cwes(89) == ["CWE-89"] and parse_cwes(0) == [] and parse_cwes(None) == []
    assert parse_cwes("CWE-502") == ["CWE-502"]


def test_rel_path_handles_windows_and_unix_styles(tmp_path):
    assert rel_path("C:\\Users\\hp\\Temp\\scan\\src\\app.py", "C:\\Users\\hp\\Temp\\scan") == "src/app.py"
    assert rel_path("c:/users/hp/temp/scan/src/app.py", "C:\\Users\\hp\\Temp\\scan") == "src/app.py"  # drive/case differences
    assert rel_path("./src/app.py", tmp_path) == "src/app.py" and rel_path(".\\src\\app.py", tmp_path) == "src/app.py"
    assert rel_path("src/app.py", tmp_path) == "src/app.py"


def test_staging_selects_files_and_disables_semgrep_default_ignores(tmp_path):
    root, dest = tmp_path / "repo", tmp_path / "scan"
    for rel, text in {"src/a.py": "x = 1\n", "tests/test_a.py": "y = 2\n", "web/app.js": "var z;\n",
                      "node_modules/dep/i.js": "var q;\n", "Main.java": "class A {}\n", "notes.txt": "hi\n"}.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    staged = stage_files(root, dest)
    assert [s.path for s in staged] == ["src/a.py", "tests/test_a.py", "web/app.js"]  # tests/ kept; java, txt, node_modules not
    assert (dest / ".semgrepignore").read_text() == ""  # empty file replaces Semgrep's default ignore list
    assert (dest / "tests" / "test_a.py").exists() and sum(s.lines for s in staged) == 3


# ---------------------------------------------------------------- normalization
def test_normalize_bandit_maps_fields_and_reads_evidence_from_the_source(stage):
    f = normalize_bandit({"results": [bandit_result()]}, stage)[0]
    assert isinstance(f, Finding)
    assert (f.cwe_id, f.severity.value, f.confidence, f.line_number, f.source) == ("CWE-78", "high", 0.6, 6, "baseline-bandit")
    assert f.message.startswith("[bandit B605] Starting a process with a shell")
    assert f.evidence == "os.system('ping ' + request.args['h'])" and f.file_path == "src/app.py"


def test_normalize_bandit_windows_paths_missing_cwe_and_multiline_range(stage):
    r = bandit_result(filename=str(stage).replace("/", "\\") + "\\src\\app.py", issue_cwe={"id": 0, "link": ""},
                      line_number=5, line_range=[5, 6], issue_severity="LOW", issue_confidence="HIGH")
    f = normalize_bandit({"results": [r]}, stage)[0]
    assert f.file_path == "src/app.py" and f.cwe_id is None
    assert (f.line_range.start, f.line_range.end) == (5, 6) and f.severity.value == "low" and f.confidence == 0.9


def test_normalize_semgrep_strips_machine_specific_rule_prefix(stage):
    r = semgrep_result(path=f"{stage}/src/app.py")
    f = normalize_semgrep({"results": [r]}, stage)[0]
    assert short_rule_id(r["check_id"]) == "python.flask.security.injection.os-system-injection"
    assert "[semgrep python.flask.security.injection.os-system-injection]" in f.message
    assert (f.cwe_id, f.severity.value, f.confidence, f.source) == ("CWE-78", "high", 0.9, "baseline-semgrep")
    assert f.evidence.startswith("os.system(")  # "requires login" is never used as evidence


def test_normalize_semgrep_filters_non_security_rules_keeps_multi_cwe_and_unknown_confidence(stage):
    noise = semgrep_result(extra={"message": "style", "severity": "WARNING",
                                  "metadata": {"category": "best-practice"}})
    multi = semgrep_result(path=f"{stage}/src/app.py", extra={
        "message": "Dynamic code.", "severity": "WARNING",
        "metadata": {"category": "security", "cwe": ["CWE-95: Eval Injection", "CWE-94: Code Injection"]}})
    out = normalize_semgrep({"results": [noise, multi]}, stage)
    assert len(out) == 1 and out[0].cwe_id == "CWE-95" and "Also tagged: CWE-94" in out[0].explanation
    assert out[0].confidence == 0.5 and out[0].severity.value == "medium"


def test_finding_ids_are_stable_and_validate_against_the_shared_schema(stage):
    a = normalize_bandit({"results": [bandit_result()]}, stage)[0]
    b = normalize_bandit({"results": [bandit_result()]}, stage)[0]
    assert a.finding_id == b.finding_id and a.finding_id.startswith("bandit-")
    Finding.model_validate(a.model_dump(mode="json"))


def test_dedupe_merges_rules_on_the_same_line_but_not_different_tools_or_cwes(stage):
    rows = [semgrep_result(path=f"{stage}/src/app.py", check_id=f"x.semgrep-rules.python.r{i}") for i in range(3)]
    rows[1]["extra"] = {**rows[1]["extra"], "severity": "INFO", "metadata": {**rows[1]["extra"]["metadata"], "confidence": "LOW"}}
    sem = normalize_semgrep({"results": rows}, stage)
    ban = normalize_bandit({"results": [bandit_result()]}, stage)
    assert len(sem) == 3
    merged = dedupe_by_location(sem + ban)
    assert [(f.source, f.line_number) for f in merged] == [("baseline-bandit", 6), ("baseline-semgrep", 6)]
    assert [f for f in merged if f.source == "baseline-semgrep"][0].severity.value == "high"


# ---------------------------------------------------------------- end to end (needs the real tools)
@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit not installed")
def test_bandit_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "app.py").write_text(APP)
    (repo / "tests" / "test_app.py").write_text(APP)
    meta = run_baselines(str(repo), str(tmp_path / "out"), tools=("bandit",), repeat=2)
    b = meta["tools"]["bandit"]
    assert b["available"] and b["errors"] == [] and b["files_scanned"] == 2 and b["lines_scanned"] == 12
    assert len(b["runs"]) == 2 and b["median_seconds_total"] > 0
    rows = [json.loads(l) for l in (tmp_path / "out" / "c1_findings.jsonl").read_text().splitlines()]
    assert {r["file_path"] for r in rows} == {"app.py", "tests/test_app.py"}  # tests/ is scanned
    assert any(r["cwe_id"] == "CWE-78" and r["line_number"] == 6 for r in rows)
    for r in rows:
        Finding.model_validate(r)
    log = json.loads((tmp_path / "out" / "run_log.json").read_text())
    RunLog.model_validate(log[0])
    assert log[0]["model"].startswith("bandit ") and (tmp_path / "out" / "bandit_raw.json").exists()


def test_missing_tools_are_reported_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr("analysis_engine.baselines.bandit_runner.find_tool", lambda name: None)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("x = 1\n")
    meta = run_baselines(str(repo), str(tmp_path / "out"), tools=("bandit",))
    assert meta["tools"]["bandit"]["available"] is False and "pip install bandit" in meta["tools"]["bandit"]["errors"][0]
    assert (tmp_path / "out" / "c1_findings.jsonl").read_text() == ""


@pytest.mark.skipif(not os.environ.get("RUN_SEMGREP_E2E") or shutil.which("semgrep") is None,
                    reason="slow; set RUN_SEMGREP_E2E=1 and install semgrep")
def test_semgrep_end_to_end_with_pinned_rules(tmp_path):
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "app.py").write_text(APP)
    (repo / "tests" / "test_app.py").write_text(APP)
    meta = run_baselines(str(repo), str(tmp_path / "out"), tools=("semgrep",),
                         rule_dirs=("python/flask/security", "python/lang/security"), cwes=list(SCOPE_CWES))
    s = meta["tools"]["semgrep"]
    assert s["available"] and s["errors"] == [] and s["rules_commit"] == s["rules_commit_pinned"]
    assert s["median_seconds_rule_loading"] is not None and s["median_seconds_scan"] is not None
    rows = [json.loads(l) for l in (tmp_path / "out" / "c1_findings.jsonl").read_text().splitlines()]
    assert {r["file_path"] for r in rows} == {"app.py", "tests/test_app.py"}
    assert all(r["cwe_id"] in SCOPE_CWES for r in rows) and any(r["cwe_id"] == "CWE-78" for r in rows)
