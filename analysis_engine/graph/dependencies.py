"""Module dependency graph: which file imports which."""
import networkx as nx

from analysis_engine.graph.resolve import ModuleIndex, build_bindings
from analysis_engine.parser.models import FileStructure


def dependency_cycles(graph: nx.DiGraph) -> list[list[str]]:
    """Groups of files that import each other (directly or through a chain)."""
    cycles = [sorted(c) for c in nx.strongly_connected_components(graph) if len(c) > 1]
    return sorted(cycles, key=lambda c: (-len(c), c[0]))


def build_dependency_graph(files: list[FileStructure]) -> nx.DiGraph:
    """Nodes are files. An edge A -> B means A imports B. Third-party and
    standard-library imports are not nodes; they are listed on each node under
    `external` (top-level package names)."""
    index = ModuleIndex(files)
    graph = nx.DiGraph()
    for f in files:
        graph.add_node(f.file_path, label=f.file_path, file=f.file_path, kind="module",
                       language=f.language, functions=len(f.functions), classes=len(f.classes),
                       external=[])
    all_external: set[str] = set()
    for f in files:
        bindings = build_bindings(index, f)
        for target, names in bindings.targets.items():
            if target == f.file_path:
                continue
            if graph.has_edge(f.file_path, target):
                merged = set(graph[f.file_path][target]["names"]) | names
                graph[f.file_path][target]["names"] = sorted(merged)
            else:
                graph.add_edge(f.file_path, target, names=sorted(names))
        graph.nodes[f.file_path]["external"] = sorted(bindings.external_packages)
        all_external |= bindings.external_packages
    graph.graph["stats"] = {
        "modules": graph.number_of_nodes(),
        "internal_imports": graph.number_of_edges(),
        "external_packages": sorted(all_external),
        "import_cycles": len(dependency_cycles(graph)),
    }
    return graph
