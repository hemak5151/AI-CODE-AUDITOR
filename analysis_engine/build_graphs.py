"""Build the call graph and dependency graph for a repo and export them.

Usage (from the project root):
    python -m analysis_engine.build_graphs <folder | repo.zip | git-url> --out graph_out
        [--png] [--focus NAME] [--depth 2]

Writes callgraph.json, dependencies.json, callgraph.dot, dependencies.dot
(and .png files with --png). --focus draws only the neighbourhood of one function.
"""
import argparse
import json
from pathlib import Path
from typing import Optional

from analysis_engine.graph import (build_call_graph, build_dependency_graph, dependency_cycles,
                                   ego, find_nodes, save_png, to_dot, to_json)
from analysis_engine.ingest import from_git, from_zip, iter_source_files
from analysis_engine.parser.models import FileStructure
from analysis_engine.parser.structure import extract_file


def load_structures(root: Path) -> list[FileStructure]:
    root = Path(root)
    return [extract_file(path, root) for path, _language in iter_source_files(root)]


def run(target: str, out_dir: str, png: bool = False, focus: Optional[str] = None, depth: int = 2) -> dict:
    if target.endswith(".zip"):
        root = from_zip(target)
    elif target.startswith(("http://", "https://", "git@")):
        root = from_git(target)
    else:
        root = Path(target)
    files = load_structures(root)
    calls = build_call_graph(files)
    deps = build_dependency_graph(files)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []

    def write(name: str, text: str) -> None:
        (out / name).write_text(text, encoding="utf-8")
        written.append(str(out / name))

    write("callgraph.json", json.dumps(to_json(calls), indent=2))
    write("dependencies.json", json.dumps(to_json(deps), indent=2))
    write("callgraph.dot", to_dot(calls, "Call graph"))
    write("dependencies.dot", to_dot(deps, "Module dependencies", cluster_by_file=False))
    if png:
        written.append(save_png(calls, str(out / "callgraph.png"), "Call graph"))
        written.append(save_png(deps, str(out / "dependencies.png"), "Module dependencies"))
    focus_matches: list[str] = []
    if focus:
        focus_matches = find_nodes(calls, focus)
        if focus_matches:
            sub = ego(calls, focus_matches[0], depth)
            write("focus.dot", to_dot(sub, f"Around {focus_matches[0]}"))
            if png:
                written.append(save_png(sub, str(out / "focus.png"), f"Around {focus_matches[0]}"))
    most_called = sorted(
        ((n, calls.in_degree(n)) for n, d in calls.nodes(data=True) if d.get("kind") != "module"),
        key=lambda x: (-x[1], x[0]))[:5]
    return {
        "files_parsed": len(files),
        "call_graph": calls.graph["stats"],
        "dependency_graph": {k: v for k, v in deps.graph["stats"].items() if k != "external_packages"}
                            | {"external_packages": len(deps.graph["stats"]["external_packages"])},
        "import_cycles": dependency_cycles(deps)[:5],
        "most_called": most_called,
        "focus_matches": focus_matches[:5],
        "written": written,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Build call and dependency graphs")
    ap.add_argument("target", help="folder, .zip file, or git URL")
    ap.add_argument("--out", default="graph_out", help="output folder (default graph_out)")
    ap.add_argument("--png", action="store_true", help="also draw PNG images (needs matplotlib)")
    ap.add_argument("--focus", help="function name to draw the neighbourhood of")
    ap.add_argument("--depth", type=int, default=2)
    args = ap.parse_args()
    result = run(args.target, args.out, args.png, args.focus, args.depth)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
