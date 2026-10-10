import json

import pytest

from analysis_engine.parser.structure import extract_file, extract_structure
from analysis_engine.parser.treesitter_parser import detect_language

PY = '''"""module doc"""
import os
import numpy as np
from flask import request, jsonify as jf
from . import sibling
from .utils import helper


class Base:
    pass


class Db(Base, object):
    """Database wrapper."""

    def get(self, name, limit=10, *args, **kwargs):
        """Fetch one row.

        Longer description.
        """
        def inner():
            return 1
        return name

    @staticmethod
    def make(x: int, y: str = "a"):
        return x


async def login(user):
    return user
'''

JS = '''import express from 'express';
import { a, b as c } from './mod';
import * as fs2 from 'fs';
const path = require('path');

/**
 * Hash a password.
 * @param {string} p
 */
export function hash(p) { return p; }

/** Arrow doc */
const add = (x, y = 1) => x + y;

class Repo extends Base {
  /** Find by id */
  find(id) { return id; }
}

function plain() {}
'''


def test_python_functions_methods_and_docstrings():
    s = extract_structure(PY, "python", "a.py")
    assert s.parse_error is None
    by = {f.qualified_name: f for f in s.functions}
    assert set(by) == {"Db.get", "Db.get.inner", "Db.make", "login"}
    get = by["Db.get"]
    assert get.kind == "method" and get.parent_class == "Db"
    assert get.params == ["self", "name", "limit", "*args", "**kwargs"]
    assert get.docstring.startswith("Fetch one row.")
    assert "Longer description." in get.docstring
    assert by["Db.get.inner"].kind == "function"
    assert by["Db.make"].params == ["x", "y"]
    assert by["login"].kind == "function" and by["login"].docstring is None
    assert (get.start_line, get.end_line) == (16, 23)


def test_python_classes():
    s = extract_structure(PY, "python", "a.py")
    cls = {c.name: c for c in s.classes}
    assert cls["Db"].bases == ["Base", "object"]
    assert cls["Db"].docstring == "Database wrapper."
    assert cls["Db"].methods == ["get", "make"]
    assert cls["Base"].methods == []


def test_python_imports():
    s = extract_structure(PY, "python", "a.py")
    imp = {(i.module, tuple(i.names), i.alias) for i in s.imports}
    assert ("os", (), None) in imp
    assert ("numpy", (), "np") in imp
    assert ("flask", ("request", "jsonify"), None) in imp
    assert (".", ("sibling",), None) in imp
    assert (".utils", ("helper",), None) in imp


def test_javascript_structure():
    s = extract_structure(JS, "javascript", "a.js")
    assert s.parse_error is None
    by = {f.qualified_name: f for f in s.functions}
    assert set(by) == {"hash", "add", "Repo.find", "plain"}
    assert by["hash"].docstring.startswith("Hash a password.")
    assert by["hash"].params == ["p"]
    assert by["add"].params == ["x", "y"]
    assert by["add"].docstring == "Arrow doc"
    assert by["Repo.find"].kind == "method" and by["Repo.find"].docstring == "Find by id"
    assert by["plain"].docstring is None
    repo = s.classes[0]
    assert repo.name == "Repo" and repo.bases == ["Base"] and repo.methods == ["find"]


def test_javascript_imports():
    s = extract_structure(JS, "javascript", "a.js")
    imp = {(i.module, tuple(i.names)) for i in s.imports}
    assert ("express", ("express",)) in imp
    assert ("./mod", ("a", "b")) in imp
    assert ("fs", ("*",)) in imp
    assert ("path", ()) in imp  # require()


def test_syntax_error_gives_partial_results_and_no_crash():
    s = extract_structure("def ok():\n    return 1\n\ndef broken(:\n    pass\n", "python", "bad.py")
    assert s.parse_error is not None and s.parse_error.startswith("line ")
    assert "ok" in [f.name for f in s.functions]


def test_unsupported_and_unknown_language():
    assert extract_structure("x", "cobol", "a.cob").parse_error == "unsupported language: cobol"
    assert extract_structure("x", None, "README").language == "unknown"


def test_detect_language():
    assert detect_language("a/b/c.py") == "python"
    assert detect_language("x.JSX") == "javascript"
    assert detect_language("Main.java") == "java"
    assert detect_language("run", "#!/usr/bin/env python3\nprint(1)") == "python"
    assert detect_language("run", "#!/usr/bin/env node\n") == "javascript"
    assert detect_language("notes.txt") is None


def test_java_stub_parses_but_extracts_nothing():
    pytest.importorskip("tree_sitter_java")
    ok = extract_structure("class A { void f() {} }", "java", "A.java")
    assert ok.language == "java" and ok.parse_error is None
    assert ok.functions == [] and ok.classes == []
    bad = extract_structure("class A { void f( {} }", "java", "A.java")
    assert bad.parse_error is not None


def test_deeply_nested_code_does_not_crash():
    src = "x = " + "(" * 3000 + "1" + ")" * 3000 + "\n"
    s = extract_structure(src, "python", "deep.py")
    assert s.language == "python"  # no RecursionError


def test_extract_file_bom_unreadable_and_json(tmp_path):
    f = tmp_path / "m.py"
    f.write_bytes(b"\xef\xbb\xbfdef f():\n    pass\n")
    s = extract_file(f, tmp_path)
    assert s.file_path == "m.py" and s.parse_error is None and s.functions[0].name == "f"
    json.dumps(s.model_dump())  # must be JSON-serializable
    missing = extract_file(tmp_path / "nope.py", tmp_path)
    assert missing.parse_error.startswith("could not read file")
