from analysis_engine.parser.structure import extract_structure


def test_python_calls_are_attributed_to_enclosing_function():
    src = "import os\n\ndef a():\n    b()\n    self.c()\n    os.path.join('x')\n    d().e()\n\nx = a()\n"
    s = extract_structure(src, "python", "a.py")
    assert [c.name for c in s.functions[0].calls] == ["b", "self.c", "os.path.join", "d"]
    assert [c.name for c in s.module_calls] == ["a"]  # call outside any function
    assert s.functions[0].calls[0].line == 4


def test_nested_function_calls_go_to_the_inner_function():
    src = "def outer():\n    def inner():\n        helper()\n    inner()\n"
    s = extract_structure(src, "python", "a.py")
    by = {f.qualified_name: [c.name for c in f.calls] for f in s.functions}
    assert by == {"outer": ["inner"], "outer.inner": ["helper"]}


def test_python_import_aliases_recorded():
    s = extract_structure("from x import a as b, c\n", "python", "a.py")
    imp = s.imports[0]
    assert imp.names == ["a", "c"] and imp.local_names == {"b": "a"}


def test_javascript_calls_new_and_require_bindings():
    src = ("const { b } = require('./b');\nconst u = require('./a');\nrequire('side');\n"
           "function z(){ b(); u.a(); new K(); }\n")
    s = extract_structure(src, "javascript", "z.js")
    assert [c.name for c in s.functions[0].calls] == ["b", "u.a", "K"]
    imp = {(i.module, tuple(i.names), i.alias) for i in s.imports}
    assert imp == {("./b", ("b",), None), ("./a", (), "u"), ("side", (), None)}


def test_javascript_import_aliases_and_namespace():
    s = extract_structure("import { a as c, d } from './m';\nimport * as ns from './n';\n", "javascript", "a.js")
    by = {i.module: i for i in s.imports}
    assert by["./m"].names == ["a", "d"] and by["./m"].local_names == {"c": "a"}
    assert by["./n"].names == ["*"] and by["./n"].alias == "ns"
