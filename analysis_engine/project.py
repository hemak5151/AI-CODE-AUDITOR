"""A loaded repo: files, sources, parse trees and the call graph, built once and shared.

    Project.from_root(path)           a folder on disk
    Project.from_sources({path: text})  in-memory code (snippets, tests, benchmark items)
"""
from pathlib import Path
from typing import Optional

from analysis_engine.graph.callgraph import CallResolver, build_call_graph
from analysis_engine.ingest import iter_source_files
from analysis_engine.parser.models import FileStructure, FunctionInfo
from analysis_engine.parser.structure import extract_structure
from analysis_engine.parser.treesitter_parser import detect_language, parse_tree, walk

FUNC_TYPES = {
    "python": {"function_definition"},
    "javascript": {"function_declaration", "generator_function_declaration", "method_definition",
                   "arrow_function", "function_expression", "function", "generator_function"},
}


TEST_DIRS = {"tests", "test", "__tests__", "spec", "examples", "example", "docs"}


def is_test_or_example_path(path: str) -> bool:
    """tests/, examples/, test_*.py, *_test.py, *.test.js, *.spec.js"""
    parts = path.split("/")
    name = parts[-1]
    return (any(p in TEST_DIRS for p in parts[:-1]) or name.startswith("test_") or name.endswith("_test.py")
            or ".test." in name or ".spec." in name)


class Project:
    def __init__(self, files: list[FileStructure], sources: dict[str, str]):
        self.files = files
        self.sources = sources
        self.file_map = {f.file_path: f for f in files}
        self._trees: dict = {}
        self._func_nodes: dict = {}
        self._resolver: Optional[CallResolver] = None
        self._call_graph = None

    # -- construction --------------------------------------------------
    @classmethod
    def from_sources(cls, sources: dict[str, str]) -> "Project":
        files, kept = [], {}
        for path, text in sources.items():
            language = detect_language(path, text)
            if language is None:
                continue
            files.append(extract_structure(text, language, path))
            kept[path] = text
        return cls(files, kept)

    @classmethod
    def from_root(cls, root) -> "Project":
        root = Path(root)
        sources = {}
        for path, _language in iter_source_files(root):
            sources[path.relative_to(root).as_posix()] = path.read_bytes().decode("utf-8-sig", errors="replace")
        return cls.from_sources(sources)

    # -- shared analyses (built lazily) --------------------------------
    @property
    def resolver(self) -> CallResolver:
        if self._resolver is None:
            self._resolver = CallResolver(self.files)
        return self._resolver

    @property
    def call_graph(self):
        if self._call_graph is None:
            self._call_graph = build_call_graph(self.files)
        return self._call_graph

    def tree(self, path: str):
        if path not in self._trees:
            self._trees[path] = parse_tree(self.sources[path], self.file_map[path].language)
        return self._trees[path]

    def function_nodes(self, path: str) -> dict:
        """(start_line, end_line) -> Tree-Sitter node, for every function-like node in the file."""
        if path not in self._func_nodes:
            nodes: dict = {}
            tree = self.tree(path)
            kinds = FUNC_TYPES.get(self.file_map[path].language, set())
            if tree is not None:
                for n in walk(tree.root_node):
                    if n.type in kinds:
                        nodes.setdefault((n.start_point[0] + 1, n.end_point[0] + 1), n)
            self._func_nodes[path] = nodes
        return self._func_nodes[path]

    def function_node(self, path: str, fn: FunctionInfo):
        return self.function_nodes(path).get((fn.start_line, fn.end_line))

    def lines(self, path: str) -> list[str]:
        return self.sources[path].splitlines()

    def is_entry_point(self, path: str, qualified_name: str) -> bool:
        """A function nobody in the repo calls: its parameters may carry outside input."""
        nid = f"{path}::{qualified_name}"
        g = self.call_graph
        return nid in g and g.in_degree(nid) == 0
