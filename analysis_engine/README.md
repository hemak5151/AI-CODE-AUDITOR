# analysis_engine: deterministic analysis (Member 1)

Parses Python and JavaScript repos, builds call and dependency graphs, tracks untrusted data from sources to
dangerous calls, and packages the result as `Finding` and `ContextPackage` objects for the LLM agents. No LLM is used here.

## Quick start
```
python -m analysis_engine.pipeline <folder | repo.zip | git-url> --out analysis_out   # findings, contexts, metrics
python -m analysis_engine.build_graphs <folder> --out graph_out --png                 # call + dependency graphs
python -m analysis_engine.figures <folder> --out figures                               # paper figures (PNG, PDF)
python -m analysis_engine.baselines <folder> --out baseline_out                        # C1: Bandit + Semgrep
python -m analysis_engine.ablation <folder> --out ablation_inputs.jsonl                # C2 / C3 inputs
python -m analysis_engine.static_eval --out static_eval_out                            # labelled dev set, 3 tools
```
In code: `analyze_job(root, progress)` (one call per backend job), `AnalysisSession` (incremental), `analyze_sources({...})`.
Details: `docs/member1_context_api.md` (API) and `docs/member1_baselines.md` (baselines).

## Pipeline
| Stage | Module |
|---|---|
| Ingest (folder, zip, git; skips node_modules, venv, vendor, minified) | `ingest.py` |
| Parse with Tree-Sitter; functions, classes, imports, docstrings, calls | `parser/` |
| Import resolution, call graph, dependency graph | `graph/` |
| Taint analysis (sources, sinks, sanitizers in YAML), secrets, deprecated APIs, risky calls | `security/` |
| Complexity metrics and code smells | `metrics.py` |
| Token-budgeted context packages | `context/builder.py` |
| One-call integration, incremental sessions | `integration.py`, `pipeline.py` |

## Finding sources (how strong is the evidence)
`taint-engine` (proven flow from an untrusted source) > `pattern-rule` (dangerous call with a non-constant argument, no
flow proven) > `taint-engine-entry` (parameter of an uncalled top-level function reaches a sink). Also `secret-scan`,
`deprecated-api`, `metrics`. Scope: CWE-89, 78, 22, 502, 95, 798 (plus 477 for deprecated APIs).

## Extending the rules
Edit `security/rule_data/taint.yaml` (sources, sinks, sanitizers, secret names) and `deprecated.yaml`. No code change needed.

## Performance (measured)
| Repo | Size | Result |
|---|---|---|
| Django | 3,050 files, 560k lines | 12 s load + 38 s analysis, about 540 MB (was 98 s and 1.6 GB) |
| click | 91 files, 30k lines | taint analysis 0.76 s (was 3.0 s) |
| Update of one file (Django) | | about 2.5 s |

## Limits
No type inference (`obj.method()` on a variable is not followed); branches are merged and loops run once, so an
allow-list check or a path-prefix check does not clear taint; JavaScript functions defined by assignment are only partly
extracted; Java is parse-only. Call-graph resolution is about 57% of in-repo calls on click.

## Tests
`python -m pytest analysis_engine/tests -q` (about 160 tests, 91% line coverage). Tool-dependent tests skip themselves.
Slow Semgrep test: `set RUN_SEMGREP_E2E=1`.
