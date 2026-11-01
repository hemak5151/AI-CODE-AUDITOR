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
  - `taint-engine-entry`: a function nobody calls takes a parameter that reaches a sink. A weak hint (confidence about 0.5 to 0.6), skipped in `tests/` and `examples/`.
  - `secret-scan`, `deprecated-api`, `metrics`: pattern-based.
- **Scope.** Five CWEs: 89 (SQL injection), 78 (command injection), 22 (path traversal), 502 (insecure deserialization), 95 (code injection), plus 798 (hardcoded secrets) and 477 (deprecated API). Languages: Python and JavaScript. Java is parse-only.
- **Secrets are masked** in `evidence` and never appear in any output.
- **Known blind spots** (so the LLM's second opinion is worth having): no type inference, so `obj.method()` on a variable is not followed; branches are merged and loops run once; JavaScript functions defined by assignment (`app.use = function () {}`) are not extracted.
- **Rules are data.** Sources, sinks and sanitizers live in `analysis_engine/security/rule_data/taint.yaml` and can be extended without code changes.
- **Deterministic.** Same input gives the same findings, ids and context text.
- `stats["seconds_per_1000_loc"]` is only meaningful on repos of a few thousand lines or more.
