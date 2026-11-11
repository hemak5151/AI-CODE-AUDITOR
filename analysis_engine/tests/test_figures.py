import pytest

pytest.importorskip("matplotlib")
from analysis_engine.figures import plot_call_graph, plot_taint_path  # noqa: E402
from analysis_engine.project import Project  # noqa: E402
from analysis_engine.security.taint import find_taint_flows  # noqa: E402
from analysis_engine.tests.test_ablation import SRC  # noqa: E402


def test_figures_are_written(tmp_path):
    p = Project.from_sources(SRC)
    flow = [f for f in find_taint_flows(p) if not f.entry_param][0]
    out = plot_taint_path(flow.steps, str(tmp_path / "t"), "x") + plot_call_graph(p.call_graph, "db.py::get_user", str(tmp_path / "g"))
    assert len(out) == 4 and all((tmp_path / n).stat().st_size > 1000 for n in ("t.png", "t.pdf", "g.png", "g.pdf"))
