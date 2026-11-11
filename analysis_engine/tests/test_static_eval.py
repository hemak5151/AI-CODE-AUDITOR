from analysis_engine.static_eval import build_cases, run_ours, score


def test_cases_are_well_formed():
    cases = build_cases()
    assert len(cases) > 60 and all(c.sink_line > 0 for c in cases if c.vulnerable)
    assert all("SINK" not in c.files[c.sink_file] for c in cases if c.sink_file)


def test_scoring_counts_tp_fp_fn_tn():
    cases = build_cases()
    vuln = next(c for c in cases if c.vulnerable)
    safe = next(c for c in cases if not c.vulnerable)
    hit = {"cwe_id": vuln.cwe, "file_path": vuln.sink_file, "line_number": vuln.sink_line}
    fp = {"cwe_id": safe.cwe, "file_path": "x.py", "line_number": 1}
    s = score([vuln, safe], {vuln.id: [hit], safe.id: [fp]}, strict=True)
    assert (s["tp"], s["fp"], s["fn"], s["tn"]) == (1, 1, 0, 0)
    s = score([vuln, safe], {}, strict=True)
    assert (s["tp"], s["fp"], s["fn"], s["tn"]) == (0, 0, 1, 1)


def test_our_engine_finds_something_on_the_dev_set():
    cases = build_cases()
    assert score(cases, run_ours(cases)["ours_proven"], strict=False)["tp"] > 0
