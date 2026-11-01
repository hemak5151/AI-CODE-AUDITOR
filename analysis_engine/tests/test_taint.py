from analysis_engine.project import Project
from analysis_engine.security.rule_loader import load_taint_rules
from analysis_engine.security.taint import find_taint_flows, flow_to_finding


def flows(sources, **kw):
    return find_taint_flows(Project.from_sources(sources), **kw)


def hits(sources, **kw):
    return sorted((f.cwe, f.sink_file, f.sink_line) for f in flows(sources, **kw))


# ---------------------------------------------------------------- direct flows (Python)
def test_sql_injection_through_string_concat():
    src = ("from flask import request\nimport sqlite3\n\n"
           "def view():\n    name = request.args.get('name')\n    cur = sqlite3.connect('x').cursor()\n"
           "    cur.execute(\"SELECT * FROM u WHERE n='\" + name + \"'\")\n")
    assert hits({"a.py": src}) == [("CWE-89", "a.py", 7)]


def test_sql_injection_through_fstring_and_format():
    src = ("from flask import request\n\n"
           "def a(cur):\n    n = request.form['n']\n    cur.execute(f\"SELECT * FROM t WHERE n={n}\")\n\n"
           "def b(cur):\n    n = request.form['n']\n    cur.execute('SELECT {}'.format(n))\n")
    assert hits({"a.py": src}) == [("CWE-89", "a.py", 5), ("CWE-89", "a.py", 9)]


def test_parameterized_query_is_not_flagged():
    src = ("from flask import request\n\n"
           "def v(cur):\n    n = request.args.get('n')\n    cur.execute('SELECT * FROM t WHERE n=?', (n,))\n")
    assert hits({"a.py": src}) == []


def test_command_injection_and_shell_requirement():
    src = ("import os, subprocess\nfrom flask import request\n\n"
           "def a():\n    os.system('ping ' + request.form['h'])\n\n"
           "def b():\n    subprocess.run(request.args['c'], shell=True)\n\n"
           "def c():\n    subprocess.run(['ping', request.args['c']])\n")
    assert hits({"a.py": src}) == [("CWE-78", "a.py", 5), ("CWE-78", "a.py", 8)]


def test_path_traversal_and_basename_sanitizer():
    src = ("import os\nfrom flask import request\n\n"
           "def bad():\n    return open(os.path.join('/data', request.args['f'])).read()\n\n"
           "def good():\n    return open(os.path.join('/data', os.path.basename(request.args['f']))).read()\n")
    assert hits({"a.py": src}) == [("CWE-22", "a.py", 5)]


def test_insecure_deserialization_and_safe_yaml_loader():
    src = ("import pickle, yaml\nfrom flask import request\n\n"
           "def a():\n    return pickle.loads(request.data)\n\n"
           "def b():\n    return yaml.load(request.data, Loader=yaml.SafeLoader)\n\n"
           "def c():\n    return yaml.load(request.data)\n")
    assert hits({"a.py": src}) == [("CWE-502", "a.py", 5), ("CWE-502", "a.py", 11)]


def test_numeric_conversion_sanitizes_everything():
    src = ("from flask import request\n\n"
           "def v(cur):\n    i = int(request.args['id'])\n    cur.execute('SELECT * FROM t WHERE id=' + str(i))\n")
    assert hits({"a.py": src}) == []


def test_shlex_quote_only_protects_command_injection():
    src = ("import os, shlex\nfrom flask import request\n\n"
           "def v():\n    os.system('ls ' + shlex.quote(request.args['d']))\n\n"
           "def w():\n    open(shlex.quote(request.args['d']))\n")
    assert hits({"a.py": src}) == [("CWE-22", "a.py", 8)]


def test_import_alias_is_expanded():
    src = ("from os import system as run_cmd\nfrom flask import request\n\n"
           "def v():\n    run_cmd(request.args['c'])\n")
    assert hits({"a.py": src}) == [("CWE-78", "a.py", 5)]


def test_input_builtin_and_tuple_unpacking():
    src = "import os\n\ndef v():\n    a, b = input(), 'x'\n    os.system(a)\n"
    assert hits({"a.py": src}) == [("CWE-78", "a.py", 5)]


def test_reassigning_a_constant_clears_taint():
    src = ("import os\nfrom flask import request\n\n"
           "def v():\n    c = request.args['c']\n    c = 'ls'\n    os.system(c)\n")
    assert hits({"a.py": src}) == []


# ---------------------------------------------------------------- across functions and files
def test_flow_through_helper_in_another_file():
    routes = ("from flask import request\nfrom db import get_user\n\n"
              "def login():\n    name = request.args.get('n')\n    return get_user(name)\n")
    db = "def get_user(name):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % name)\n"
    fl = flows({"routes.py": routes, "db.py": db})
    assert [(f.cwe, f.sink_file, f.sink_line, f.interprocedural) for f in fl if not f.entry_param] == [
        ("CWE-89", "db.py", 2, True)]
    path = [s.kind for s in next(f for f in fl if not f.entry_param).steps]
    assert path[0] == "source" and "call" in path and path[-1] == "sink"


def test_flow_through_two_levels_of_wrappers():
    src = ("import os\nfrom flask import request\n\n"
           "def inner(c):\n    os.system(c)\n\n"
           "def middle(c):\n    inner('x ' + c)\n\n"
           "def view():\n    middle(request.args['c'])\n")
    real = [f for f in flows({"a.py": src}) if not f.entry_param]
    assert [(f.sink_line, f.interprocedural) for f in real] == [(5, True)]


def test_taint_returned_from_a_function():
    src = ("import os\nfrom flask import request\n\n"
           "def read():\n    return request.args.get('x')\n\n"
           "def view():\n    v = read()\n    os.system(v)\n")
    assert [f.sink_line for f in flows({"a.py": src}) if not f.entry_param] == [9]


def test_constant_argument_is_safe_and_hides_entry_point():
    src = ("import os\n\ndef run(cmd):\n    os.system(cmd)\n\ndef main():\n    run('ls')\n")
    assert hits({"a.py": src}) == []


def test_method_call_through_self():
    src = ("import os\nfrom flask import request\n\n"
           "class H:\n    def run(self, c):\n        os.system(c)\n\n"
           "    def get(self):\n        self.run(request.args['c'])\n")
    real = [f for f in flows({"a.py": src}) if not f.entry_param]
    assert [(f.sink_line, f.interprocedural) for f in real] == [(6, True)]


# ---------------------------------------------------------------- entry points
def test_uncalled_function_parameters_are_treated_as_input_with_lower_confidence():
    src = "import subprocess\n\ndef run(user_input):\n    subprocess.run(user_input, shell=True)\n"
    fl = flows({"a.py": src})
    assert [(f.cwe, f.sink_line, f.entry_param) for f in fl] == [("CWE-78", 4, True)]
    f = flow_to_finding(fl[0], load_taint_rules(), Project.from_sources({"a.py": src}))
    assert f.confidence < 0.7 and "parameter 'user_input'" in f.explanation
    assert flows({"a.py": src}, entry_point_params=False) == []


# ---------------------------------------------------------------- JavaScript
def test_javascript_express_handlers():
    src = ("const express = require('express');\nconst { exec } = require('child_process');\n"
           "const fs = require('fs');\nconst app = express();\n\n"
           "app.get('/ping', (req, res) => {\n  exec('ping ' + req.query.host);\n});\n\n"
           "app.get('/user', (req, res) => {\n  db.query(`SELECT * FROM u WHERE id=${req.params.id}`);\n});\n\n"
           "app.get('/safe', (req, res) => {\n  db.query('SELECT * FROM u WHERE id=?', [req.params.id]);\n});\n\n"
           "app.get('/file', (req, res) => {\n  fs.readFile(req.query.name, () => {});\n});\n\n"
           "app.post('/run', (req, res) => {\n  eval(req.body.code);\n});\n")
    # the parameterized query on line 15 is safe and must not be reported
    assert hits({"app.js": src}) == sorted([
        ("CWE-78", "app.js", 7), ("CWE-89", "app.js", 11), ("CWE-22", "app.js", 19), ("CWE-95", "app.js", 23)])


def test_javascript_flow_through_a_function_and_sanitizer():
    src = ("const { exec } = require('child_process');\n\n"
           "function ping(host) {\n  exec('ping ' + host);\n}\n\n"
           "app.get('/a', (req, res) => {\n  ping(req.query.h);\n});\n\n"
           "app.get('/b', (req, res) => {\n  ping(parseInt(req.query.h));\n});\n")
    real = [f for f in flows({"app.js": src}) if not f.entry_param]
    assert [(f.sink_line, f.source_line) for f in real] == [(4, 8)]


def test_javascript_destructured_request_data():
    src = "const { exec } = require('child_process');\napp.get('/', (req, res) => {\n  const { cmd } = req.query;\n  exec(cmd);\n});\n"
    assert hits({"app.js": src}) == [("CWE-78", "app.js", 4)]


def test_many_entry_points_reaching_one_sink_are_reported_once():
    src = ("import os\n\ndef _run(c):\n    os.system(c)\n\n"
           "def a(x):\n    _run(x)\n\ndef b(y):\n    _run(y)\n\ndef c(z):\n    _run(z)\n")
    fl = flows({"a.py": src})
    assert len(fl) == 1 and fl[0].entry_param
    assert "other uncalled functions" in fl[0].source_desc and "(and 2 " in fl[0].source_desc


def test_entry_point_findings_are_labelled_separately_from_real_source_flows():
    src = ("import os\nfrom flask import request\n\ndef real():\n    os.system(request.args['c'])\n\n"
           "def weak(cmd):\n    os.system(cmd)\n")
    p = Project.from_sources({"a.py": src})
    rules = load_taint_rules()
    labels = {f.line_number: f.source for f in (flow_to_finding(x, rules, p) for x in find_taint_flows(p))}
    assert labels == {5: "taint-engine", 8: "taint-engine-entry"}


def test_weak_entry_point_hints_are_skipped_in_tests_and_examples_but_real_flows_are_not():
    weak = "import os\n\ndef run(cmd):\n    os.system(cmd)\n"
    real = "import os\nfrom flask import request\n\ndef view():\n    os.system(request.args['c'])\n"
    assert flows({"tests/test_a.py": weak, "examples/b.py": weak, "test_c.py": weak}) == []
    assert len(flows({"src/a.py": weak})) == 1
    assert len(flows({"tests/test_a.py": real})) == 1  # a real source is reported anywhere


def test_with_open_binding_carries_taint_to_a_later_sink():
    src = ("import yaml\nfrom flask import request\nfrom werkzeug.utils import secure_filename\n\n"
           "def upload():\n    f = request.files['file']\n    name = secure_filename(f.filename)\n"
           "    with open('/data/' + name) as fh:\n        text = fh.read()\n    return yaml.load(text)\n")
    # the file name was sanitized for path traversal (no CWE-22), but the contents are still untrusted (CWE-502)
    assert hits({"a.py": src}) == [("CWE-502", "a.py", 10)]


def test_more_request_sources_and_mathjs_sink():
    js = ("const serialize = require('node-serialize');\nconst mathjs = require('mathjs');\n"
          "app.post('/a', (req, res) => {\n  serialize.unserialize(req.files.products.data.toString('utf8'));\n});\n"
          "app.post('/b', (req, res) => {\n  res.json(mathjs.eval(req.body.eqn));\n});\n")
    assert hits({"app.js": js}) == sorted([("CWE-502", "app.js", 4), ("CWE-95", "app.js", 7)])
