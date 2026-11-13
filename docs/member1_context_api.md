# Member 1 → Member 3: analysis engine and context package API

Everything here is deterministic (no LLM) and produces the shared `Finding` and `ContextPackage` models from `shared/schemas`. No shared schema was changed.

## Quick start

```python
from analysis_engine.pipeline import analyze_repo, analyze_sources

result = analyze_repo("path/to/repo")                  # a folder
result = analyze_sources({"a.py": code, "b.js": code}) # in-memory code (snippets, benchmark items)

result.findings   # list[Finding]            taint flows, hardcoded secrets, deprecated APIs
result.contexts   # {finding_id: ContextPackage}
result.smells     # list[Finding]            complexity / code-smell findings (cwe_id is None)
result.metrics    # list[FunctionMetrics]
result.stats      # counts and runtime per 1,000 lines
```

Command line (writes `findings.json`, `contexts.json`, `smells.json`, `metrics.json`, `summary.json`):

```
python -m analysis_engine.pipeline <folder | repo.zip | git-url> --out analysis_out --budget 2000
```

## For the backend: one call per job

```python
from analysis_engine.integration import analyze_job

result = analyze_job(root, progress)      # root = the extracted upload or clone
result.findings        # list of Finding dicts (shared schema, JSON-ready), most severe first
result.sources         # {path: text} of every file a finding refers to (including files along a taint path)
result.contexts        # {finding_id: ContextPackage dict}
result.files_scanned
```

`progress(stage, done, total)` is called while it works; the stages come in this order: `parse`, `scan`, `taint`. It covers Python and JavaScript, follows data across files, and is safe to run for several jobs in different threads at once. `backend/app/services/jobs.py` uses it.

## Re-analysing after a change (patch validation)

`AnalysisSession` analyses a repo once and then updates incrementally. After you change one file, only that file and the code that depends on it are re-analysed, and the result is identical to a full analysis (this is tested).

```python
from analysis_engine.pipeline import AnalysisSession
from analysis_engine.project import Project

session = AnalysisSession(Project.from_root("path/to/repo"))   # or Project.from_sources({...})
before = session.analyze()                       # full analysis, once
after = session.update_file("app/db.py", patched_source)   # about 2 s even on a 560,000-line repo
session.findings_for("app/db.py")                # findings of one file in the latest result
session.update_file("app/old.py", None)          # None removes a file
```

A patch fixed a finding when the same CWE no longer appears near its location in `after.findings` (line numbers can shift, so compare by CWE and file, with a few lines of tolerance). Do this on a copy of the project or call `update_file` again with the original source to roll back. The patch must be applied in the sandbox as usual; `update_file` only reads source text and never runs it.

## Context package

One `ContextPackage` per finding, built around the function that contains the vulnerable line.

| Field | Contents |
|---|---|
| `target_function` | call-graph node id, `"path/file.py::Class.method"`, or `"path/file.py::<module>"` for top-level code |
| `callers` / `callees` | node ids of direct callers / callees (max 25 each) |
| `imports` | imports of the file, `"module"` or `"module.name"` |
| `taint_path` | ordered steps, each `"file:line kind: code"`; kind is `source`, `propagation`, `call`, `sanitizer` or `sink`. Empty for secrets/deprecated findings |
| `token_trimmed_context` | prompt-ready text, **guaranteed within the token budget** |

`token_trimmed_context` is built in priority order and trimmed from the bottom:
1. the target function, with line numbers (windowed around the sink line if it is too big)
2. the taint path
3. call sites in the callers (with one line of context)
4. signatures of called functions (with the first docstring line)
5. imports

Token counts use `characters / 4` by default. To use the real tokenizer of your model:

```python
from analysis_engine.context.builder import build_context
pkg = build_context(project, "db.py::get_user", flow=None, budget_tokens=2000, count_tokens=my_token_counter)
```

## Example (real output)

Finding (`source` is `"taint-engine"`, `confidence` 0.81 because the flow crosses a function boundary):

```json
{
  "finding_id": "CWE-89-3c2e91dc",
  "cwe_id": "CWE-89",
  "severity": "high",
  "confidence": 0.81,
  "message": "SQL injection via cur.execute()",
  "file_path": "db.py",
  "line_number": 6,
  "evidence": "request.args.get('n')  [routes.py:6]\n-> name = ...  [routes.py:6]\n-> get_user(...)  [routes.py:7]\n-> cur.execute(...)  [db.py:6]",
  "source": "taint-engine"
}
```

Its context package:

```text
## Target: db.py::get_user (lines 4-7)
   4 | def get_user(name):
   5 |     cur = sqlite3.connect('app.db').cursor()
   6 |     cur.execute("SELECT * FROM users WHERE name='%s'" % name)
   7 |     return cur.fetchone()

## Taint path (source -> sink)
- routes.py:6 source: request.args.get('n')
- routes.py:6 propagation: name = ...
- routes.py:7 call: get_user(...)
- db.py:6 sink: cur.execute(...)

## Call sites

# routes.py::login calls this at line 7
   6 |     name = request.args.get('n')
   7 |     return get_user(name)

## Imports
sqlite3
```

## Things to know when using the findings

- **`Finding.source` tells you how strong the evidence is.**
  - `taint-engine`: a real source (request data, `input()`, ...) reaches a sink. Strong.
  - `pattern-rule`: a dangerous call (`eval`/`exec`, shell commands with `shell=True` or `os.system`) with a **non-constant argument**, but no proven data flow (confidence about 0.5). When a proven flow exists on the same line, the `taint-engine` finding replaces it.
  - `taint-engine-entry`: a top-level function nobody calls takes a parameter that reaches a sink. A weak hint (confidence about 0.5 to 0.6), skipped in `tests/` and `examples/`. Class methods are not treated as entry points by default (in library code almost every method is uncalled inside the repo); pass `entry_point_methods=True` or `--entry-methods` to include them.
  - `secret-scan`, `deprecated-api`, `metrics`: pattern-based.
- **Scope.** Five CWEs: 89 (SQL injection), 78 (command injection), 22 (path traversal), 502 (insecure deserialization), 95 (code injection), plus 798 (hardcoded secrets) and 477 (deprecated API). Languages: Python and JavaScript. Java is parse-only.
- **Secrets are masked** in `evidence` and never appear in any output.
- **Known blind spots** (so the LLM's second opinion is worth having): no type inference, so `obj.method()` on a variable is not followed; branches are merged and loops run once; JavaScript functions defined by assignment (`app.use = function () {}`) are not extracted.
- **Rules are data.** Sources, sinks and sanitizers live in `analysis_engine/security/rule_data/taint.yaml` and can be extended without code changes.
- **Deterministic.** Same input gives the same findings, ids and context text.
- `stats["seconds_per_1000_loc"]` is only meaningful on repos of a few thousand lines or more. For scale: Django (560,000 lines, 3,050 files) takes about 12 s to load and 38 s to analyse using about 540 MB; `click` (30,000 lines) takes about 2 s.
- Hardcoded secrets: names such as `password` or `api_key` are reported for any non-placeholder value; the weaker name `token` only when the value looks like a real secret. Names that say the value is a label or location (`..._prefix`, `..._url`, `..._message`, `..._source`, ...) are ignored. Credentials in `tests/` and `examples/` folders are not reported by default (fake credentials there are normal); pass `include_tests=True` to `analyze_job`, `analyze_repo` or `AnalysisSession`, or `--include-tests` on the command line, to include them. Known token formats such as AWS keys are reported everywhere. Weak real passwords such as `"secret"` are reported; only fill-in markers such as `changeme` or `<password>` are skipped.
