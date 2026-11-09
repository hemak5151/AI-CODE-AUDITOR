import json
from concurrent.futures import ThreadPoolExecutor

from analysis_engine.integration import analyze_job
from analysis_engine.pipeline import AnalysisSession, analyze_sources
from analysis_engine.project import Project
from shared.schemas import ContextPackage, Finding

ROUTES = "from flask import request\nfrom db import get_user\n\n\ndef login():\n    return get_user(request.args.get('n'))\n"
DB = "def get_user(name):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % name)\n"
APP_JS = "app.post('/run', (req, res) => {\n  eval(req.body.code);\n});\n"


def make_repo(root, newline="\n"):
    files = {"routes.py": ROUTES, "db.py": DB, "web/app.js": APP_JS, "README.md": "# hi\n", "Main.java": "class A {}\n",
             "node_modules/x/index.js": "eval(req.body.z);\n", "clean.py": "def add(a, b):\n    return a + b\n"}
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(text.replace("\n", newline).encode())  # exact bytes: no per-OS newline conversion
    return root


def test_analyze_job_returns_json_ready_findings_sources_and_contexts(tmp_path):
    r = analyze_job(make_repo(tmp_path))
    json.dumps(r.findings)
    for item in r.findings:
        Finding.model_validate(item)
    assert sorted((f["cwe_id"], f["file_path"]) for f in r.findings) == [("CWE-89", "db.py"), ("CWE-95", "web/app.js")]
    for item in r.contexts.values():
        ContextPackage.model_validate(item)
    assert set(r.contexts) == {f["finding_id"] for f in r.findings}
    assert r.files_scanned == 5  # routes.py, db.py, web/app.js, Main.java, clean.py (node_modules and README skipped)


def test_sources_include_every_file_along_a_taint_path_but_not_clean_files(tmp_path):
    r = analyze_job(make_repo(tmp_path))
    assert set(r.sources) == {"db.py", "routes.py", "web/app.js"}  # routes.py is where the taint starts
    assert r.sources["routes.py"] == ROUTES


def test_progress_reports_each_stage_in_order_and_finishes(tmp_path):
    calls = []
    analyze_job(make_repo(tmp_path), lambda stage, done, total: calls.append((stage, done, total)))
    stages = [c[0] for c in calls]
    assert stages == sorted(stages, key=["parse", "scan", "taint"].index)  # never goes backwards
    for stage in ("parse", "scan", "taint"):
        mine = [c for c in calls if c[0] == stage]
        assert mine and mine[-1][1] == mine[-1][2]                        # ends at done == total
        assert [c[1] for c in mine] == sorted(c[1] for c in mine)


def test_empty_repo_is_fine(tmp_path):
    r = analyze_job(tmp_path)
    assert (r.findings, r.sources, r.files_scanned) == ([], {}, 0)


def test_many_jobs_in_threads_give_the_same_answers_as_one_at_a_time():
    variants = [{"routes.py": ROUTES, "db.py": DB},
                {"a.py": "import os\n\ndef run(c):\n    os.system(c)\n"},
                {"a.js": APP_JS},
                {"s.py": "PASSWORD = 'hunter2-prod'\nimport imp\n"}]

    def fingerprint(sources):
        r = analyze_sources(dict(sources))
        return [(f.finding_id, f.line_number, f.evidence) for f in r.findings], \
            {k: v.token_trimmed_context for k, v in r.contexts.items()}

    expected = [fingerprint(v) for v in variants]
    with ThreadPoolExecutor(max_workers=8) as pool:
        got = list(pool.map(lambda i: fingerprint(variants[i % 4]), range(48)))
    assert all(got[i] == expected[i % 4] for i in range(48))


def test_sessions_in_threads_can_update_independently():
    def work(n):
        s = AnalysisSession(Project.from_sources({"a.py": "x = 1\n", "b.py": f"def f{n}():\n    return {n}\n"}))
        s.analyze()
        r = s.update_file("a.py", "import os\n\ndef run(c):\n    os.system(c)\n")
        return [f.cwe_id for f in r.findings]

    with ThreadPoolExecutor(max_workers=6) as pool:
        assert list(pool.map(work, range(24))) == [["CWE-78"]] * 24


def test_windows_line_endings_give_the_same_findings_as_unix_ones(tmp_path):
    (tmp_path / "u").mkdir()
    (tmp_path / "w").mkdir()
    a = analyze_job(make_repo(tmp_path / "u", "\n"))
    b = analyze_job(make_repo(tmp_path / "w", "\r\n"))

    def shape(r):
        return ([(f["finding_id"], f["line_number"], f["evidence"], f["confidence"]) for f in r.findings],
                {k: v["token_trimmed_context"] for k, v in r.contexts.items()}, r.files_scanned)

    assert shape(a) == shape(b)
    assert "\r\n" in b.sources["routes.py"] and "\r" not in a.sources["routes.py"]  # file text itself is untouched
