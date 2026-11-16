from analysis_engine.reproduce import EXPECTED, run


def test_reproduction_matches_the_numbers_in_the_paper_for_our_engine(tmp_path):
    rep = run(tmp_path, {"ours"})
    assert rep["checks"]["cases"] == "PASS" and rep["checks"]["ours_proven"] == "PASS"
    assert rep["checks"]["bandit"].startswith("SKIP") and rep["ok"]
    assert (tmp_path / "repro_report.md").exists() and EXPECTED["cases"] == 68
