import json

import pytest

from analysis_engine.build_graphs import run
from analysis_engine.graph import build_call_graph, ego, find_nodes, save_png, to_dot, to_json
from analysis_engine.ingest import iter_source_files
from analysis_engine.parser.structure import extract_file

SRC = {
    "a.py": "from b import g\n\ndef f():\n    g()\n\ndef lone():\n    pass\n",
    "b.py": "def g():\n    h()\n\ndef h():\n    pass\n",
}


def _repo(tmp_path):
    for rel, text in SRC.items():
        (tmp_path / rel).write_text(text)
    return tmp_path


def _graph(tmp_path):
    root = _repo(tmp_path)
    return build_call_graph([extract_file(p, root) for p, _ in iter_source_files(root)])


def test_to_dot_has_clusters_edges_and_escapes_quotes(tmp_path):
    g = _graph(tmp_path)
    g.nodes["a.py::f"]["label"] = 'f"quoted"'
    dot = to_dot(g, "My graph")
    assert dot.startswith("digraph G {") and dot.rstrip().endswith("}")
    assert 'label="a.py"' in dot and 'label="b.py"' in dot  # one cluster per file
    assert '"a.py::f" -> "b.py::g";' in dot
    assert 'f\\"quoted\\"' in dot


def test_to_json_is_serializable_and_complete(tmp_path):
    data = to_json(_graph(tmp_path))
    json.dumps(data)
    assert {n["id"] for n in data["nodes"]} == {"a.py::f", "a.py::lone", "b.py::g", "b.py::h"}
    assert {"source": "a.py::f", "target": "b.py::g", "count": 1, "lines": [4]} in data["edges"]


def test_ego_graph_limits_to_neighbourhood(tmp_path):
    g = _graph(tmp_path)
    assert set(ego(g, "a.py::f", 1).nodes) == {"a.py::f", "b.py::g"}
    assert set(ego(g, "a.py::f", 2).nodes) == {"a.py::f", "b.py::g", "b.py::h"}
    assert find_nodes(g, "lone") == ["a.py::lone"]


def test_save_png_writes_an_image(tmp_path):
    pytest.importorskip("matplotlib")
    out = tmp_path / "out" / "g.png"
    save_png(_graph(tmp_path), str(out), "t")
    assert out.exists() and out.stat().st_size > 1000


def test_build_graphs_cli_writes_all_outputs(tmp_path):
    (tmp_path / "repo").mkdir()
    repo = _repo(tmp_path / "repo")
    out = tmp_path / "out"
    result = run(str(repo), str(out), png=False, focus="g", depth=1)
    names = {p.split("/")[-1].split("\\")[-1] for p in result["written"]}
    assert names == {"callgraph.json", "dependencies.json", "callgraph.dot", "dependencies.dot", "focus.dot"}
    assert result["call_graph"]["edges"] == 2
    assert result["dependency_graph"]["internal_imports"] == 1
    assert result["most_called"][0][1] == 1
    assert json.loads((out / "callgraph.json").read_text())["stats"]["edges"] == 2
