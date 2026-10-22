from analysis_engine.graph import build_dependency_graph, dependency_cycles
from analysis_engine.ingest import iter_source_files
from analysis_engine.parser.structure import extract_file


def _files(tmp_path, tree):
    for rel, text in tree.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return [extract_file(p, tmp_path) for p, _ in iter_source_files(tmp_path)]


def test_python_dependencies_relative_absolute_and_external(tmp_path):
    g = build_dependency_graph(_files(tmp_path, {
        "app/__init__.py": "",
        "app/main.py": "import requests\nimport os\nfrom . import util\nfrom .models import User\nfrom app.db import connect\n",
        "app/util.py": "",
        "app/models.py": "class User: pass\n",
        "app/db.py": "def connect(): pass\n",
    }))
    assert set(g.successors("app/main.py")) == {"app/util.py", "app/models.py", "app/db.py"}
    assert g["app/main.py"]["app/models.py"]["names"] == ["User"]
    assert g.nodes["app/main.py"]["external"] == ["os", "requests"]
    assert g.graph["stats"]["external_packages"] == ["os", "requests"]


def test_src_layout_absolute_imports(tmp_path):
    g = build_dependency_graph(_files(tmp_path, {
        "src/pkg/__init__.py": "",
        "src/pkg/a.py": "from pkg.b import x\n",
        "src/pkg/b.py": "x = 1\n",
    }))
    assert g.has_edge("src/pkg/a.py", "src/pkg/b.py")


def test_javascript_dependencies(tmp_path):
    g = build_dependency_graph(_files(tmp_path, {
        "a.js": "import x from './lib/x';\nimport y from './lib';\nimport _ from 'lodash';\nconst z = require('../outside');\n",
        "lib/x.js": "export default 1;\n",
        "lib/index.js": "export default 2;\n",
    }))
    assert set(g.successors("a.js")) == {"lib/x.js", "lib/index.js"}
    assert g.nodes["a.js"]["external"] == ["lodash"]


def test_import_cycles_are_reported(tmp_path):
    g = build_dependency_graph(_files(tmp_path, {
        "a.py": "import b\n", "b.py": "import a\n", "c.py": "import a\n",
    }))
    assert dependency_cycles(g) == [["a.py", "b.py"]]
    assert g.graph["stats"]["import_cycles"] == 1
