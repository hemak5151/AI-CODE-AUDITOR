import pytest

from analysis_engine.graph import build_call_graph, callees, callers, find_nodes
from analysis_engine.parser.structure import extract_file
from analysis_engine.ingest import iter_source_files

FILES = {
    "pkg/__init__.py": "from .core import run\n",
    "pkg/core.py": (
        "import os\n"
        "from .utils import helper, Tool\n\n"
        "def run(x):\n"
        "    helper(x)\n"
        "    t = Tool()\n"
        "    t.go()\n"
        "    return os.getcwd()\n\n"
        "class Engine:\n"
        "    def start(self):\n"
        "        self.stop()\n"
        "        return len('a')\n"
        "    def stop(self):\n"
        "        pass\n\n"
        "class Turbo(Engine):\n"
        "    def boost(self):\n"
        "        self.stop()\n"
    ),
    "pkg/utils.py": (
        "def helper(v):\n    return clean(v)\n\n"
        "def clean(v):\n    return v\n\n"
        "class Tool:\n"
        "    def __init__(self):\n        pass\n"
        "    def go(self):\n        pass\n"
    ),
    "main.py": (
        "from pkg import run\n"
        "import pkg.core as core\n\n"
        "def main():\n"
        "    run(1)\n"
        "    core.run(2)\n"
        "    nested()\n"
        "    def nested():\n        pass\n"
    ),
}


@pytest.fixture
def graph(tmp_path):
    for rel, text in FILES.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    files = [extract_file(p, tmp_path) for p, _ in iter_source_files(tmp_path)]
    return build_call_graph(files)


def test_same_file_and_cross_file_edges(graph):
    assert graph.has_edge("pkg/core.py::run", "pkg/utils.py::helper")     # from-import
    assert graph.has_edge("pkg/utils.py::helper", "pkg/utils.py::clean")  # same file
    assert graph.has_edge("pkg/core.py::Engine.start", "pkg/core.py::Engine.stop")  # self.method


def test_constructor_call_resolves_to_init(graph):
    assert graph.has_edge("pkg/core.py::run", "pkg/utils.py::Tool.__init__")


def test_inherited_method_resolves_to_base_class(graph):
    assert graph.has_edge("pkg/core.py::Turbo.boost", "pkg/core.py::Engine.stop")


def test_nested_function_resolves_inside_its_parent(graph):
    assert graph.has_edge("main.py::main", "main.py::main.nested")


def test_reexport_chain_and_module_alias(graph):
    # "from pkg import run" goes through pkg/__init__.py to pkg/core.py
    assert graph.has_edge("main.py::main", "pkg/core.py::run")
    assert graph["main.py::main"]["pkg/core.py::run"]["count"] == 2  # run(1) and core.run(2)


def test_stats_separate_external_builtin_and_unresolved(graph):
    st = graph.graph["stats"]
    assert st["external"] == 1       # os.getcwd
    assert st["builtin"] == 1        # len
    assert st["unresolved"] == 1     # t.go(): receiver is a variable, no type inference
    assert "t.go" in graph.nodes["pkg/core.py::run"]["unresolved"]
    assert 0 < st["resolution_rate"] < 1


def test_callers_and_callees_queries(graph):
    assert callees(graph, "pkg/core.py::run") == ["pkg/utils.py::Tool.__init__", "pkg/utils.py::helper"]
    assert callees(graph, "pkg/core.py::run", depth=2) == [
        "pkg/utils.py::Tool.__init__", "pkg/utils.py::clean", "pkg/utils.py::helper"]
    assert callers(graph, "pkg/utils.py::clean", depth=2) == ["pkg/core.py::run", "pkg/utils.py::helper"]
    assert callers(graph, "pkg/utils.py::clean", depth=3) == [
        "main.py::main", "pkg/core.py::run", "pkg/utils.py::helper"]
    assert find_nodes(graph, "Engine.stop") == ["pkg/core.py::Engine.stop"]
    assert find_nodes(graph, "stop") == ["pkg/core.py::Engine.stop"]


def test_javascript_graph(tmp_path):
    (tmp_path / "a.js").write_text(
        "import { b as bee, c } from './b';\nimport * as ns from './b';\n"
        "class K { m(){ this.n(); } n(){} }\n"
        "function a(){ bee(); c(); ns.d(); new K(); console.log(1); }\n")
    (tmp_path / "b.js").write_text(
        "export function b(){}\nexport function c(){ d(); }\nexport function d(){}\n")
    (tmp_path / "c.js").write_text("const { b } = require('./b');\nconst u = require('./a');\nfunction z(){ b(); u.a(); }\n")
    files = [extract_file(p, tmp_path) for p, _ in iter_source_files(tmp_path)]
    g = build_call_graph(files)
    assert g.has_edge("a.js::a", "b.js::b")        # aliased named import
    assert g.has_edge("a.js::a", "b.js::c")
    assert g.has_edge("a.js::a", "b.js::d")        # namespace import: ns.d()
    assert g.has_edge("b.js::c", "b.js::d")
    assert g.has_edge("a.js::K.m", "a.js::K.n")    # this.method
    assert g.has_edge("a.js::a", "a.js::K")        # new K(): class without explicit constructor
    assert g.has_edge("c.js::z", "b.js::b")        # require destructuring
    assert g.has_edge("c.js::z", "a.js::a")        # require alias: u.a()
    assert g.graph["stats"]["builtin"] == 1        # console.log
