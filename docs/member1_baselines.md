# Member 1 → Member 2: C1 baseline results (Bandit + Semgrep)

C1 is the deterministic baseline: **Bandit** (Python) and **Semgrep Community Edition** (Python + JavaScript), normalized to the shared `Finding` schema. The same staged files are given to both tools, so they always scan an identical file set.

## Install the tools in their own environment

Semgrep pins `opentelemetry-api` to an older version than the backend's packages need, so installing both in one virtual environment makes pip warn about a conflict. Keep Semgrep and Bandit in a separate environment **outside the repo**, and tell the runner where they are:

```
python -m venv %USERPROFILE%\.venvs\ai-auditor-tools
%USERPROFILE%\.venvs\ai-auditor-tools\Scripts\pip install -r analysis_engine\requirements-baselines.txt
set SEMGREP_CMD=%USERPROFILE%\.venvs\ai-auditor-tools\Scripts\semgrep.exe
set BANDIT_CMD=%USERPROFILE%\.venvs\ai-auditor-tools\Scripts\bandit.exe
```

(`set` lasts for the current Command Prompt window only.) If these variables are not set, the runner uses whatever is on `PATH`.

## Run it

```
python -m analysis_engine.baselines <folder | repo.zip | git-url> --out baseline_out [--repeat 3] [--cwes scope]
```

Scan the **whole benchmark folder in one run**. Semgrep spends about a minute loading rules before it scans anything, so one run per sample would be very slow.

## Output files (in `--out`)

| File | Contents |
|---|---|
| `c1_findings.jsonl` | one shared `Finding` per line, both tools. `source` is `baseline-bandit` or `baseline-semgrep` |
| `baseline_meta.json` | tool versions, Semgrep rules commit, commands, **list of every file scanned**, lines of code, timings |
| `run_log.json` | one shared `RunLog` per tool (`model` = tool + version, `prompt_version` = `rules@<commit>`, `latency_ms`) |
| `bandit_raw.json`, `semgrep_raw.json` | the tools' own output, for traceability |

`message` always starts with the tool's rule id, for example `[semgrep python.flask.security.injection.os-system-injection] ...` or `[bandit B605] ...`.

## Field mapping

| `Finding` field | Bandit | Semgrep |
|---|---|---|
| `cwe_id` | `issue_cwe.id` (None if 0 or missing) | first entry of `metadata.cwe` (others are listed in `explanation`) |
| `severity` | HIGH / MEDIUM / LOW → high / medium / low | ERROR / WARNING / INFO → high / medium / low |
| `confidence` | `issue_confidence`: HIGH 0.9, MEDIUM 0.6, LOW 0.3 | `metadata.confidence`, same scale; 0.5 if the rule has none |
| `evidence` | the source line, read from the file | the source line, read from the file (Semgrep hides it without a login) |

Semgrep results from non-security rules (best-practice, correctness, performance) are dropped unless the rule carries a CWE.

## How to evaluate fairly

1. **A file with no findings is not "missing".** `baseline_meta.json → files` lists every file that was scanned, so you can tell "scanned and clean" from "not scanned".
2. **Merge duplicate locations.** Semgrep often reports one line from several rules. Use `analysis_engine.baselines.common.dedupe_by_location(findings)` before counting true/false positives.
3. **Restrict to the claimed CWEs.** `SCOPE_CWES` = 89, 78, 22, 502, 798, 95; `--cwes scope` applies it. The tools also report other CWEs (for example 704, 915), which should not count against them. Decide as a team whether related CWEs count as a match (for example 77 for 78, 94 for 95, 259 for 798) and write the mapping in the paper.
4. **Bandit flags imports.** `import pickle` is reported as CWE-502 at the import line. That is genuine Bandit behavior (a pattern match, no data flow), so match findings to labels by function or line range, not by file alone.
5. **Bandit covers Python only.** JavaScript results in C1 come from Semgrep alone.

## Timing

`baseline_meta.json → tools.<name>` has `median_seconds_total`, `median_seconds_rule_loading`, `median_seconds_scan`, `seconds_per_1000_loc_total` and `seconds_per_1000_loc_scan`.

Semgrep's total time is dominated by a fixed rule-loading cost (about 70 s for roughly 500 rule files) that does not grow with code size; the scan itself is fast. For "analysis time per 1,000 LOC" report the **scan** figure, and mention the rule-loading cost separately. Use `--repeat 3` for the final numbers (the median is reported) and `--jobs 1` (the default) so Semgrep and Bandit are comparable. Timings are only meaningful on a benchmark of a few thousand lines or more.

## Reproducibility and licensing

- Versions are pinned in `analysis_engine/requirements-baselines.txt` (Bandit 1.9.4, Semgrep 1.183.0).
- Semgrep rules are pinned to **semgrep-rules commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`** (2026-10-21). They are downloaded on first use to `~/.cache/ai-code-auditor/semgrep-rules`, outside the repo. Override the location with `AI_AUDITOR_CACHE` or `--rules-dir`.
- **Do not copy the Semgrep rules into the repo or into the released toolkit.** The Semgrep Rules License v1.0 allows internal use only and forbids redistributing the rules or offering them as a service. The open toolkit should ship the fetch script and this commit hash, not the rules. Whether publishing the *result* files (rule ids and messages) is fine should be confirmed with the team lead; we are not lawyers.
- C1 uses the free Community engine. To our knowledge, Semgrep's cross-file analysis is part of its paid Pro engine, so say in the paper that C1 is the Community engine.
