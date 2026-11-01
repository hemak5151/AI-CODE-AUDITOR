from analysis_engine.metrics import compute_metrics, smell_findings
from analysis_engine.project import Project


def metrics(sources, **kw):
    return {m.qualified_name: m for m in compute_metrics(Project.from_sources(sources), **kw)}


def test_python_complexity_and_nesting():
    src = ("def f(a, b, c, d, e, f, g, self=None):\n"
           "    if a and b:\n"
           "        for x in c:\n"
           "            while d:\n"
           "                if e or f:\n"
           "                    pass\n"
           "    elif g:\n"
           "        pass\n"
           "    return [i for i in a if i]\n")
    m = metrics({"a.py": src})["f"]
    # 1 + if + and + for + while + if + or + elif + comprehension-for + comprehension-if
    assert m.cyclomatic == 10
    assert m.max_nesting == 4
    assert m.params == 7 and "too-many-params" in m.smells and m.loc == 9


def test_simple_function_has_no_smells():
    m = metrics({"a.py": "def f(x):\n    return x + 1\n"})["f"]
    assert (m.cyclomatic, m.max_nesting, m.params, m.smells) == (1, 0, 1, [])


def test_self_is_not_counted_and_nested_functions_are_separate():
    src = ("class C:\n    def m(self, a):\n        def inner(b):\n            if b:\n                return 1\n"
           "            return 2\n        return inner(a)\n")
    got = metrics({"a.py": src})
    assert got["C.m"].params == 1 and got["C.m"].cyclomatic == 1  # inner's `if` is not counted in m
    assert got["C.m.inner"].cyclomatic == 2


def test_javascript_logical_operators_and_else_if_chain():
    src = ("function f(a, b) {\n  if (a && b) {\n    return 1;\n  } else if (a || b) {\n    return 2;\n"
           "  } else if (b) {\n    return 3;\n  }\n  return a ? 4 : 5;\n}\n")
    m = metrics({"a.js": src})["f"]
    # 1 + if + && + if(else-if) + || + if(else-if) + ternary
    assert m.cyclomatic == 7
    assert m.max_nesting == 1  # else-if chain is flat


def test_thresholds_and_smell_findings():
    src = "def f(a):\n" + "".join(f"    if a == {i}:\n        pass\n" for i in range(11)) + "    return a\n"
    ms = compute_metrics(Project.from_sources({"a.py": src}))
    assert ms[0].cyclomatic == 12 and ms[0].smells == ["high-complexity"]
    fl = smell_findings(ms)
    assert len(fl) == 1 and fl[0].cwe_id is None and fl[0].severity.value == "info"
    assert compute_metrics(Project.from_sources({"a.py": src}), thresholds={"high-complexity": 20})[0].smells == []


def test_smell_ids_are_stable_across_runs():
    src = "def f(a):\n" + "".join(f"    if a == {i}:\n        pass\n" for i in range(11)) + "    return a\n"
    a = smell_findings(compute_metrics(Project.from_sources({"a.py": src})))
    b = smell_findings(compute_metrics(Project.from_sources({"a.py": src})))
    assert [f.finding_id for f in a] == [f.finding_id for f in b]
    assert a[0].finding_id == "smell-high-complexity-" + a[0].finding_id.split("-")[-1] and len(a[0].finding_id.split("-")[-1]) == 8
