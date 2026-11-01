import pytest

from analysis_engine.context.builder import build_context, estimate_tokens, target_for_line
from analysis_engine.project import Project
from analysis_engine.security.taint import find_taint_flows
from shared.schemas import ContextPackage

ROUTES = ("from flask import request\nfrom db import get_user, log\n\n\n"
          "def login():\n    name = request.args.get('n')\n    log('login')\n    return get_user(name)\n")
DB = ("import sqlite3\n\n\n"
      "def log(msg):\n    \"\"\"Write a log line.\"\"\"\n    print(msg)\n\n\n"
      "def get_user(name):\n    cur = sqlite3.connect('x').cursor()\n"
      "    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % name)\n    return cur.fetchone()\n")


@pytest.fixture
def project():
    return Project.from_sources({"routes.py": ROUTES, "db.py": DB})


def _flow(project):
    return next(f for f in find_taint_flows(project) if not f.entry_param)


def test_context_for_a_cross_file_flow(project):
    flow = _flow(project)
    pkg = build_context(project, "db.py::get_user", flow)
    assert isinstance(pkg, ContextPackage)
    assert pkg.target_function == "db.py::get_user"
    assert pkg.callers == ["routes.py::login"]
    assert pkg.callees == []
    assert "sqlite3" in pkg.imports
    assert pkg.taint_path[0].startswith("routes.py:6 source:") and pkg.taint_path[-1].endswith("sink: cur.execute(...)")
    text = pkg.token_trimmed_context
    assert "## Target: db.py::get_user (lines 9-12)" in text
    assert "  11 |     cur.execute(" in text  # line numbers let the model cite exact lines
    assert "routes.py::login calls this at line 8" in text


def test_callee_signatures_include_docstring_summary(project):
    pkg = build_context(project, "routes.py::login")
    assert pkg.callees == ["db.py::get_user", "db.py::log"]
    assert "def log(msg):    # Write a log line." in pkg.token_trimmed_context


def test_budget_is_respected_and_target_survives(project):
    big = "def f(x):\n" + "".join(f"    y{i} = x + {i}\n" for i in range(400)) + "    return y1\n"
    p = Project.from_sources({"big.py": big})
    for budget in (150, 400, 1000):
        pkg = build_context(p, "big.py::f", budget_tokens=budget)
        assert estimate_tokens(pkg.token_trimmed_context) <= budget
        assert "## Target: big.py::f" in pkg.token_trimmed_context
        assert "def f(x):" in pkg.token_trimmed_context  # signature always kept


def test_large_target_is_windowed_around_the_sink():
    body = "".join(f"    a{i} = {i}\n" for i in range(200))
    src = "import os\n\ndef f(x):\n" + body + "    os.system(x)\n"
    p = Project.from_sources({"a.py": src})
    flow = next(iter(find_taint_flows(p)))
    pkg = build_context(p, "a.py::f", flow, budget_tokens=300)
    assert "os.system(x)" in pkg.token_trimmed_context
    assert "lines omitted" in pkg.token_trimmed_context
    assert estimate_tokens(pkg.token_trimmed_context) <= 300


def test_custom_token_counter_is_used(project):
    pkg = build_context(project, "db.py::get_user", budget_tokens=5000, count_tokens=lambda t: len(t))
    assert len(pkg.token_trimmed_context) <= 5000


def test_module_level_target_and_line_lookup(project):
    assert target_for_line(project, "db.py", 11) == "db.py::get_user"
    assert target_for_line(project, "db.py", 1) == "db.py::<module>"
    pkg = build_context(project, "db.py::<module>")
    assert "top-level code of db.py" in pkg.token_trimmed_context
