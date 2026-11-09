from analysis_engine.pipeline import AnalysisSession, analyze_sources
from analysis_engine.project import Project
from analysis_engine.security.patterns import find_risky_patterns, is_constant


def risky(sources):
    return find_risky_patterns(Project.from_sources(sources))


def got(sources):
    return sorted((f.cwe_id, f.line_number, f.source) for f in risky(sources))


def test_eval_and_exec_with_a_non_constant_argument_are_reported():
    src = "eval(user_input)\nexec(code)\neval('1 + 1')\nexec('print(1)')\neval(f'{x}')\n"
    assert got({"a.py": src}) == [("CWE-95", 1, "pattern-rule"), ("CWE-95", 2, "pattern-rule"), ("CWE-95", 5, "pattern-rule")]


def test_shell_true_needs_a_non_constant_command_and_the_shell_flag():
    src = ("import os, subprocess\n"
           "subprocess.run('echo ' + name, shell=True)\n"      # 2: dynamic + shell
           "subprocess.run('ls -l', shell=True)\n"              # constant command
           "subprocess.run(['ls', name])\n"                     # no shell
           "subprocess.run(cmd, shell=False)\n"                 # shell explicitly off
           "os.system(cmd)\n"                                   # 6
           "os.system('ls')\n")
    assert got({"a.py": src}) == [("CWE-78", 2, "pattern-rule"), ("CWE-78", 6, "pattern-rule")]


def test_import_aliases_are_expanded():
    assert got({"a.py": "from os import system as run_cmd\nrun_cmd(cmd)\n"}) == [("CWE-78", 2, "pattern-rule")]


def test_javascript_patterns():
    src = "const { exec } = require('child_process');\nexec(cmd);\neval(code);\neval('1');\nexec('ls');\n"
    assert got({"a.js": src}) == [("CWE-78", 2, "pattern-rule"), ("CWE-95", 3, "pattern-rule")]


def test_pattern_findings_are_weaker_than_proven_flows_and_say_so():
    f = risky({"a.py": "eval(x)\n"})[0]
    assert f.confidence == 0.5 and f.severity.value == "critical" and "not a proven vulnerability" in f.explanation
    assert f.evidence == "eval(x)" and f.finding_id.startswith("CWE-95-p")


def test_sql_and_other_cwes_are_not_pattern_reported():
    assert risky({"a.py": "cur.execute('SELECT ' + name)\nopen(path)\npickle.loads(data)\n"}) == []


def test_constant_detection():
    p = Project.from_sources({"a.py": "x = ('a' + 'b')\ny = 'a' + z\nw = f'{z}'\nn = 5\n"})
    from analysis_engine.parser.treesitter_parser import nodes_of_types
    values = [n.child_by_field_name("right") for n in nodes_of_types(p.tree("a.py"), "python", ("assignment",))]
    assert [is_constant(v) for v in values] == [True, False, False, True]


def test_a_proven_flow_replaces_the_pattern_finding_on_the_same_line():
    src = "import os\nfrom flask import request\n\n\ndef view():\n    os.system(request.args['c'])\n\n\ndef other(cmd):\n    os.system(cmd)\n"
    r = analyze_sources({"a.py": src})
    by_line = {f.line_number: f.source for f in r.findings}
    assert by_line == {6: "taint-engine", 10: "taint-engine-entry"}  # one finding per line, the stronger one


def test_pattern_only_when_no_flow_is_proven():
    r = analyze_sources({"a.py": "password = 'demo-secret'\neval(user_input)\n"})
    assert sorted((f.cwe_id, f.source) for f in r.findings) == sorted([("CWE-798", "secret-scan"), ("CWE-95", "pattern-rule")])


def test_incremental_update_keeps_pattern_findings_consistent():
    s = AnalysisSession(Project.from_sources({"a.py": "x = 1\n"}))
    s.analyze()
    s.update_file("a.py", "eval(code)\n")
    assert [(f.cwe_id, f.source) for f in s.result.findings] == [("CWE-95", "pattern-rule")]
    fresh = analyze_sources({"a.py": "eval(code)\n"})
    assert [f.finding_id for f in s.result.findings] == [f.finding_id for f in fresh.findings]
    s.update_file("a.py", "x = 1\n")
    assert s.result.findings == []


def test_a_bare_exec_is_not_a_shell_command_unless_imported_from_child_process():
    regexp_helper = "function exec(re, s) { return re.exec(s); }\nconst m = exec(re, input);\nconst n = pattern.exec(text);\n"
    assert got({"a.js": regexp_helper}) == []
    assert got({"a.js": "const cp = require('child_process');\ncp.exec(cmd);\n"}) == [("CWE-78", 2, "pattern-rule")]
    assert got({"a.js": "import { execSync } from 'child_process';\nexecSync(cmd);\n"}) == [("CWE-78", 2, "pattern-rule")]
