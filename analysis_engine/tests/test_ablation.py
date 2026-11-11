from analysis_engine.ablation import build_ablation_inputs, candidates
from analysis_engine.project import Project

SRC = {"routes.py": "from flask import request\nfrom db import get_user\n\n\ndef view():\n    return get_user(request.args.get('n'))\n",
       "db.py": "def get_user(name):\n    cur.execute(\"SELECT * FROM u WHERE n='\" + name + \"'\")\n\n\ndef helper():\n    return 1\n"}


def test_candidates_are_functions_that_call_dangerous_apis():
    assert candidates(Project.from_sources(SRC)) == [("db.py", "get_user")]


def test_c2_c3_and_taint_variants_differ_only_by_added_context():
    items = build_ablation_inputs(Project.from_sources(SRC))
    assert [i["item_id"] for i in items] == ["db.py::get_user"]
    it = items[0]
    assert it["c2"]["callers"] == [] and it["c3"]["callers"] == ["routes.py::view"]
    assert "calls this at line" in it["c3"]["context_text"] and "calls this" not in it["c2"]["context_text"]
    assert it["c3"]["taint_path"] == [] and it["c3_taint"]["available"] and it["c3_taint"]["taint_path"]
    assert it["c2"]["tokens"] < it["c3"]["tokens"] <= it["c3_taint"]["tokens"]
