from analysis_engine.parser.treesitter_parser import parse_code

PY = """import os
import numpy as np
from flask import request

class Db:
    def get(self, name):
        return name

def login(user):
    return user
"""

JS = """import express from 'express';
const fs = require('fs');

class Repo {
  find(id) { return id; }
}

function login(user) { return user; }
const hash = (p) => p;
"""


def test_python_extraction():
    r = parse_code(PY, "python")
    assert r.parse_error is None
    assert r.functions == ["get", "login"]
    assert r.classes == ["Db"]
    assert r.imports == ["flask", "numpy", "os"]
    assert r.line_ranges["login"] == (9, 10)


def test_javascript_extraction():
    r = parse_code(JS, "javascript")
    assert r.parse_error is None
    assert r.functions == ["find", "hash", "login"]
    assert r.classes == ["Repo"]
    assert r.imports == ["express", "fs"]


def test_syntax_error_does_not_crash():
    r = parse_code("def broken(:\n    pass\n", "python")
    assert r.parse_error is not None
    assert r.parse_error.startswith("line ")


def test_unsupported_language():
    r = parse_code("class A {}", "java")
    assert r.parse_error == "unsupported language: java"
