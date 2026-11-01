import json
from pathlib import Path

from analysis_engine.pipeline import analyze_repo, analyze_sources, write_outputs
from shared.schemas import ContextPackage, Finding

SOURCES = {
    "routes.py": ("import os\nfrom flask import request\nfrom db import get_user\n\n"
                  "API_KEY = 'prod-key-123456'\n\n"
                  "def login():\n    name = request.args.get('n')\n    return get_user(name)\n\n"
                  "def ping():\n    os.system('ping ' + request.form['h'])\n"),
    "db.py": ("import imp\n\ndef get_user(name):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % name)\n"),
}


def test_all_detectors_run_and_every_finding_has_a_context():
    r = analyze_sources(SOURCES)
    kinds = sorted((f.cwe_id, f.file_path, f.line_number) for f in r.findings)
    assert kinds == [("CWE-477", "db.py", 1), ("CWE-78", "routes.py", 12), ("CWE-798", "routes.py", 5),
                     ("CWE-89", "db.py", 4)]
    assert set(r.contexts) == {f.finding_id for f in r.findings}
    assert all(isinstance(c, ContextPackage) for c in r.contexts.values())


def test_findings_are_sorted_by_severity_first():
    sev = [f.severity.value for f in analyze_sources(SOURCES).findings]
    assert sev == sorted(sev, key=["critical", "high", "medium", "low", "info"].index)


def test_taint_finding_carries_evidence_and_a_context_around_the_sink_function():
    r = analyze_sources(SOURCES)
    sqli = next(f for f in r.findings if f.cwe_id == "CWE-89")
    assert sqli.source == "taint-engine" and "-> " in sqli.evidence
    ctx = r.contexts[sqli.finding_id]
    assert ctx.target_function == "db.py::get_user" and ctx.callers == ["routes.py::login"]
    assert ctx.taint_path[0].startswith("routes.py:8 source:")


def test_secret_values_never_appear_in_any_output():
    r = analyze_sources(SOURCES)
    blob = json.dumps([f.model_dump(mode="json") for f in r.findings])
    assert "prod-key-123456" not in blob.replace("redacted", "")  # masked in evidence
    assert "prod-key-123456" not in json.dumps({k: v.evidence for k, v in [(f.finding_id, f) for f in r.findings]})


def test_results_are_deterministic():
    a, b = analyze_sources(SOURCES), analyze_sources(SOURCES)
    assert [f.finding_id for f in a.findings] == [f.finding_id for f in b.findings]
    assert {k: v.token_trimmed_context for k, v in a.contexts.items()} == {k: v.token_trimmed_context for k, v in b.contexts.items()}


def test_stats_include_runtime_per_1000_loc():
    s = analyze_sources(SOURCES).stats
    assert s["files"] == 2 and s["lines_of_code"] > 0 and s["seconds_per_1000_loc"] is not None
    assert s["findings_by_cwe"]["CWE-89"] == 1


def test_clean_code_has_no_findings():
    r = analyze_sources({"a.py": "def add(a, b):\n    return a + b\n\ndef main():\n    print(add(1, 2))\n"})
    assert r.findings == [] and r.contexts == {}


def test_outputs_round_trip_through_the_shared_schemas(tmp_path):
    (tmp_path / "repo").mkdir()
    for name, text in SOURCES.items():
        (tmp_path / "repo" / name).write_text(text)
    r = analyze_repo(tmp_path / "repo")
    files = write_outputs(r, str(tmp_path / "out"))
    assert sorted(Path(p).name for p in files) == ["contexts.json", "findings.json", "metrics.json", "smells.json", "summary.json"]
    for item in json.loads((tmp_path / "out" / "findings.json").read_text()):
        Finding.model_validate(item)
    for item in json.loads((tmp_path / "out" / "contexts.json").read_text()).values():
        ContextPackage.model_validate(item)
