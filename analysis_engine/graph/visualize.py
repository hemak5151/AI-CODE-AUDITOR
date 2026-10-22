"""Export graphs as JSON, Graphviz DOT (for the paper), or a PNG (for debugging)."""
from pathlib import Path
from typing import Optional

import networkx as nx


def to_json(graph: nx.DiGraph) -> dict:
    return {
        "stats": graph.graph.get("stats", {}),
        "nodes": [{"id": n, **{k: v for k, v in d.items()}} for n, d in graph.nodes(data=True)],
        "edges": [{"source": a, "target": b, **d} for a, b, d in graph.edges(data=True)],
    }


def ego(graph: nx.DiGraph, node: str, depth: int = 2) -> nx.DiGraph:
    """The neighbourhood around one node (both directions), for readable pictures."""
    return graph.subgraph(nx.ego_graph(graph.to_undirected(as_view=True), node, radius=depth).nodes).copy()


def _esc(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace('"', '\\"')


def to_dot(graph: nx.DiGraph, title: str = "", cluster_by_file: bool = True) -> str:
    """Graphviz source. Render with `dot -Tpng graph.dot -o graph.png` or paste into an online viewer."""
    lines = ["digraph G {", "  rankdir=LR;", '  node [shape=box, fontsize=10, style="rounded"];']
    if title:
        lines.append(f'  label="{_esc(title)}"; labelloc=t;')
    nodes = list(graph.nodes(data=True))
    if cluster_by_file:
        by_file: dict[str, list] = {}
        for n, d in nodes:
            by_file.setdefault(d.get("file", ""), []).append((n, d))
        for i, (file, members) in enumerate(sorted(by_file.items())):
            lines.append(f'  subgraph cluster_{i} {{ label="{_esc(file)}"; style=dashed;')
            for n, d in members:
                lines.append(f'    "{_esc(n)}" [label="{_esc(d.get("label", n))}"];')
            lines.append("  }")
    else:
        for n, d in nodes:
            lines.append(f'  "{_esc(n)}" [label="{_esc(d.get("label", n))}"];')
    for a, b, d in graph.edges(data=True):
        label = f' [label="{d["count"]}"]' if d.get("count", 1) > 1 else ""
        lines.append(f'  "{_esc(a)}" -> "{_esc(b)}"{label};')
    lines.append("}")
    return "\n".join(lines) + "\n"


def save_png(graph: nx.DiGraph, path: str, title: str = "", focus: Optional[str] = None,
             depth: int = 2, max_nodes: int = 60) -> str:
    """Draw with matplotlib (optional dependency). Large graphs are trimmed to the
    most connected nodes unless a `focus` node is given."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    g = ego(graph, focus, depth) if focus and focus in graph else graph
    if g.number_of_nodes() > max_nodes:
        keep = sorted(g.nodes, key=lambda n: (-g.degree(n), n))[:max_nodes]
        g = g.subgraph(keep).copy()
    files = sorted({d.get("file", "") for _, d in g.nodes(data=True)})
    palette = plt.get_cmap("tab20")
    colors = [palette(files.index(d.get("file", "")) % 20) for _, d in g.nodes(data=True)]
    pos = nx.spring_layout(g, seed=42, k=1.2 / max(g.number_of_nodes() ** 0.5, 1))
    size = min(max(8, g.number_of_nodes() * 0.35), 22)
    fig, ax = plt.subplots(figsize=(size, size * 0.7))
    nx.draw_networkx_edges(g, pos, ax=ax, arrows=True, arrowsize=12, edge_color="#888888", alpha=0.7)
    nx.draw_networkx_nodes(g, pos, ax=ax, node_color=colors, node_size=450, alpha=0.95)
    labels = {n: d.get("label", n).split("/")[-1] for n, d in g.nodes(data=True)}
    nx.draw_networkx_labels(g, pos, labels=labels, ax=ax, font_size=7)
    if title:
        ax.set_title(title)
    ax.axis("off")
    fig.tight_layout()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path
