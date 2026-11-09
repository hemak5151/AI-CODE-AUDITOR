import pytest

from analysis_engine.pipeline import AnalysisSession, analyze_sources
from analysis_engine.project import Project, is_test_or_example_path
from analysis_engine.security.taint import TaintAnalyzer, find_taint_flows

ROUTES = ("from flask import request\nfrom db import get_user\n\n\n"
          "def login():\n    name = request.args.get('n')\n    return get_user(name)\n")
DB_VULN = ("def get_user(name):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % name)\n")
DB_SAFE = "def get_user(name):\n    cur.execute('SELECT * FROM u WHERE n=?', (name,))\n"


def key(result):
    """Everything a consumer sees, as comparable data."""
    return ([(f.finding_id, f.cwe_id, f.file_path, f.line_number, f.confidence, f.evidence, f.source)
             for f in result.findings],
            {k: (v.target_function, v.callers, v.callees, v.taint_path, v.token_trimmed_context)
             for k, v in result.contexts.items()},
            [(m.file_path, m.qualified_name, m.cyclomatic) for m in result.metrics])


def check(session, sources):
    """The incremental result must equal a from-scratch analysis of the same sources."""
    assert key(session.result) == key(analyze_sources(dict(sources)))


def test_fixing_the_vulnerable_callee_removes_the_flow():
    src = {"routes.py": ROUTES, "db.py": DB_VULN}
    s = AnalysisSession(Project.from_sources(dict(src)))
    assert [f.cwe_id for f in s.analyze().findings if f.source == "taint-engine"] == ["CWE-89"]
    src["db.py"] = DB_SAFE
    assert [f for f in s.update_file("db.py", DB_SAFE).findings if f.cwe_id == "CWE-89"] == []
    check(s, src)


def test_introducing_a_vulnerability_in_the_callee_creates_a_cross_file_flow():
    src = {"routes.py": ROUTES, "db.py": DB_SAFE}
    s = AnalysisSession(Project.from_sources(dict(src)))
    assert s.analyze().findings == []
    src["db.py"] = DB_VULN
    after = s.update_file("db.py", DB_VULN)
    assert [(f.cwe_id, f.file_path) for f in after.findings] == [("CWE-89", "db.py")]
    assert "routes.py" in after.findings[0].evidence  # the path still starts in the other file
    check(s, src)


def test_changing_the_caller_stops_the_taint():
    src = {"routes.py": ROUTES, "db.py": DB_VULN}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    src["routes.py"] = ROUTES.replace("request.args.get('n')", "'admin'")
    s.update_file("routes.py", src["routes.py"])
    check(s, src)
    assert not [f for f in s.result.findings if f.source == "taint-engine"]


def test_a_function_that_becomes_uncalled_turns_into_an_entry_point():
    src = {"routes.py": ROUTES, "db.py": DB_VULN}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    src["routes.py"] = "def login():\n    return 'nothing here'\n"
    after = s.update_file("routes.py", src["routes.py"])
    assert [f.source for f in after.findings] == ["taint-engine-entry"]
    check(s, src)


def test_adding_and_deleting_files():
    src = {"routes.py": ROUTES, "db.py": DB_SAFE}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    src["extra.py"] = "import os\n\ndef run(c):\n    os.system(c)\n"
    s.update_file("extra.py", src["extra.py"])
    check(s, src)
    assert [f.file_path for f in s.result.findings] == ["extra.py"]
    del src["extra.py"]
    s.update_file("extra.py", None)
    check(s, src)
    assert s.result.findings == []


def test_a_function_returning_untrusted_data_updates_its_callers():
    src = {"lib.py": "def read():\n    return 'static'\n",
           "app.py": "import os\nfrom lib import read\n\n\ndef view():\n    os.system(read())\n"}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    # no proven flow yet: only the weak pattern-level finding (the argument is a call, not a constant)
    assert [(f.cwe_id, f.source) for f in s.result.findings] == [("CWE-78", "pattern-rule")]
    src["lib.py"] = "from flask import request\n\n\ndef read():\n    return request.args['c']\n"
    s.update_file("lib.py", src["lib.py"])
    # now the flow is proven, and it replaces the pattern finding on the same line
    assert [(f.cwe_id, f.source) for f in s.result.findings] == [("CWE-78", "taint-engine")]
    check(s, src)


def test_pattern_detectors_update_per_file():
    src = {"a.py": "x = 1\n", "b.py": "import imp\n"}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    src["a.py"] = "PASSWORD = 'hunter2-prod'\n"
    s.update_file("a.py", src["a.py"])
    assert sorted((f.file_path, f.cwe_id) for f in s.result.findings) == [("a.py", "CWE-798"), ("b.py", "CWE-477")]
    check(s, src)


def test_a_long_sequence_of_edits_always_matches_a_fresh_analysis():
    src = {"routes.py": ROUTES, "db.py": DB_VULN, "util.py": "def clean(x):\n    return int(x)\n"}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    edits = [("db.py", DB_SAFE), ("routes.py", ROUTES.replace("get_user(name)", "get_user(clean(name))").replace(
                 "from db import get_user", "from db import get_user\nfrom util import clean")),
             ("db.py", DB_VULN), ("util.py", "def clean(x):\n    return x\n"), ("util.py", None),
             ("routes.py", ROUTES), ("db.py", DB_SAFE + "\nPASSWORD = 'hunter2-prod'\n")]
    for path, text in edits:
        if text is None:
            src.pop(path, None)
        else:
            src[path] = text
        s.update_file(path, text)
        check(s, src)


def test_an_edit_only_reanalyses_what_depends_on_it(monkeypatch):
    src = {f"m{i}.py": f"import os\n\ndef f{i}(x):\n    return x + {i}\n\ndef g{i}():\n    return f{i}(1)\n" for i in range(40)}
    s = AnalysisSession(Project.from_sources(dict(src)))
    s.analyze()
    analysed = []
    original = TaintAnalyzer._analyze
    monkeypatch.setattr(TaintAnalyzer, "_analyze", lambda self, unit, ctx: (analysed.append(unit.key), original(self, unit, ctx))[1])
    s.update_file("m7.py", src["m7.py"] + "\nY = 2\n")
    assert {k[0] for k in analysed} == {"m7.py"}
    # the file's own units, plus g7 once more because f7's summary changed; none of the other 39 files
    assert len(analysed) <= 5 and len(s.project.file_map) == 40 and len(s._taint.units) == 40 * 3


def test_update_requires_a_first_analysis():
    with pytest.raises(RuntimeError):
        AnalysisSession(Project.from_sources({"a.py": "x = 1\n"})).update_file("a.py", "y = 2\n")


# ---------------------------------------------------------------- the pieces underneath
def test_project_keeps_only_a_few_parse_trees():
    p = Project.from_sources({f"f{i}.py": f"def a{i}(): pass\n" for i in range(6)}, )
    for path in sorted(p.file_map):
        p.tree(path)
        p.function_nodes(path)
    assert len(p._trees) == p.tree_cache_size == 2 and len(p._func_nodes) <= 2
    assert list(p.function_nodes("f0.py")) == [(1, 1)]  # evicted trees are rebuilt on demand


def test_nested_function_calls_belong_to_the_inner_function():
    src = ("import os\nfrom flask import request\n\n\ndef outer():\n    def inner(c):\n        os.system(c)\n"
           "    inner(request.args['c'])\n")
    real = [f for f in find_taint_flows(Project.from_sources({"a.py": src})) if not f.entry_param]
    assert [(f.sink_line, f.interprocedural) for f in real] == [(7, True)]


def test_class_methods_are_not_entry_points_unless_asked():
    src = "import os\n\nclass H:\n    def run(self, c):\n        os.system(c)\n"
    p = Project.from_sources({"a.py": src})
    assert find_taint_flows(p) == []
    assert [f.entry_param for f in find_taint_flows(p, entry_point_methods=True)] == [True]


def test_tests_py_and_conftest_count_as_test_files():
    assert all(is_test_or_example_path(p) for p in ("scripts/tests.py", "conftest.py", "a/test.py", "x/tests/y.py"))
    assert not any(is_test_or_example_path(p) for p in ("src/latest.py", "contest.py", "samples/vulnerable.py"))
