"""Figures for the paper: a call graph and a taint path (PNG and PDF).

    python -m analysis_engine.figures <folder> --out figures [--focus FunctionName]
"""
import argparse
from pathlib import Path

import networkx as nx

from analysis_engine.pipeline import AnalysisSession
from analysis_engine.project import Project
from analysis_engine.security.taint import find_taint_flows

KIND_COLOR = {"source": "#f4a582", "propagation": "#e0e0e0", "call": "#92c5de", "sanitizer": "#a6dba0", "sink": "#ca0020"}


def _save(fig, stem: str) -> list:
    out = []
    for ext, kw in ((".png", {"dpi": 200}), (".pdf", {})):
        fig.savefig(stem + ext, bbox_inches="tight", **kw)
        out.append(stem + ext)
    return out


def plot_taint_path(steps, stem: str, title: str = "") -> list:
    """steps: objects with .file .line .kind .text (the steps of a taint flow, source to sink)."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    files = list(dict.fromkeys(s.file for s in steps))
    fig, ax = plt.subplots(figsize=(3.6 * len(files) + 0.6, 1.0 * len(steps) + 1.2))
    boxes = []
    for i, s in enumerate(steps):
        x, y = files.index(s.file) * 3.6, -i * 1.0
        ax.add_patch(FancyBboxPatch((x, y - 0.32), 3.3, 0.64, boxstyle="round,pad=0.02", fc=KIND_COLOR.get(s.kind, "#fff"), ec="#444"))
        text = s.text if len(s.text) <= 38 else s.text[:35] + "..."
        ax.text(x + 0.08, y + 0.08, f"{s.kind}: {text}", fontsize=8, family="monospace", va="center")
        ax.text(x + 0.08, y - 0.17, f"{Path(s.file).name}:{s.line}", fontsize=7, color="#555", va="center")
        boxes.append((x + 1.65, y))
    for (x1, y1), (x2, y2) in zip(boxes, boxes[1:]):
        ax.add_patch(FancyArrowPatch((x1, y1 - 0.34), (x2, y2 + 0.34), arrowstyle="-|>", mutation_scale=10, color="#333", connectionstyle="arc3,rad=0.0"))
    for j, f in enumerate(files):
        ax.text(j * 3.6 + 1.65, 0.75, f, ha="center", fontsize=9, weight="bold")
    ax.set_xlim(-0.2, 3.6 * len(files)); ax.set_ylim(-len(steps) + 0.4, 1.1); ax.axis("off")
    if title:
        ax.set_title(title, fontsize=10)
    out = _save(fig, stem)
    plt.close(fig)
    return out


def plot_call_graph(graph: nx.DiGraph, focus: str, stem: str, depth: int = 2) -> list:
    """Callers on the left, the focus function in the middle, callees on the right."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    layer = {focus: 0}
    for n, d in nx.single_source_shortest_path_length(graph, focus, cutoff=depth).items():
        layer.setdefault(n, d)
    for n, d in nx.single_source_shortest_path_length(graph.reverse(copy=False), focus, cutoff=depth).items():
        layer.setdefault(n, -d)
    rows: dict = {}
    for n in sorted(layer, key=lambda n: (layer[n], n)):
        rows.setdefault(layer[n], []).append(n)
    pos = {n: (l * 3.0, -(i - (len(ns) - 1) / 2) * 0.9) for l, ns in rows.items() for i, n in enumerate(ns)}
    files = sorted({graph.nodes[n].get("file", "") for n in pos})
    palette = plt.get_cmap("tab10")
    fig, ax = plt.subplots(figsize=(2.6 * len(rows) + 1.5, 0.8 * max(len(v) for v in rows.values()) + 1.5))
    sub = graph.subgraph(pos)
    nx.draw_networkx_edges(sub, pos, ax=ax, arrows=True, arrowsize=12, edge_color="#666", node_size=2600, min_source_margin=24, min_target_margin=24)
    nx.draw_networkx_nodes(sub, pos, ax=ax, node_size=2600, node_shape="s", node_color=[palette(files.index(graph.nodes[n].get("file", "")) % 10) for n in sub],
                           edgecolors=["black" if n == focus else "#999" for n in sub], linewidths=[2.5 if n == focus else 0.8 for n in sub])
    nx.draw_networkx_labels(sub, pos, labels={n: graph.nodes[n].get("name", n).replace(".", ".\n") if len(graph.nodes[n].get("name", n)) > 14 else graph.nodes[n].get("name", n) for n in sub}, font_size=7, ax=ax)
    for i, f in enumerate(files):
        ax.plot([], [], "s", color=palette(i % 10), label=f)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=min(len(files), 3), fontsize=7, frameon=False)
    ax.axis("off")
    out = _save(fig, stem)
    plt.close(fig)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Make paper figures for a repo")
    ap.add_argument("folder")
    ap.add_argument("--out", default="figures")
    ap.add_argument("--focus", help="function whose call-graph neighbourhood to draw (default: the busiest one)")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    project = Project.from_root(Path(args.folder))
    graph = project.call_graph
    funcs = [n for n, d in graph.nodes(data=True) if d.get("kind") in ("function", "method")]
    focus = next((n for n in funcs if args.focus and (n == args.focus or graph.nodes[n]["name"] == args.focus)), None) \
        or max(funcs, key=lambda n: (graph.degree(n), n), default=None)
    written = []
    if focus:
        written += plot_call_graph(graph, focus, str(out / "call_graph"))
    flows = [f for f in find_taint_flows(project) if not f.entry_param]
    if flows:
        flow = max(flows, key=lambda f: (len({s.file for s in f.steps}), len(f.steps)))
        written += plot_taint_path(flow.steps, str(out / "taint_path"), f"{flow.cwe}: {flow.source_desc} -> {flow.sink_name}()")
    print("\n".join(written) or "nothing to draw (no functions or no proven taint flows)")


if __name__ == "__main__":
    main()
