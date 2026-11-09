"""A loaded repo: files, sources, parse trees and the call graph, built once and shared.

    Project.from_root(path)           a folder on disk
    Project.from_sources({path: text})  in-memory code (snippets, tests, benchmark items)
"""
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from analysis_engine.graph.callgraph import CallResolver, build_call_graph
from analysis_engine.ingest import iter_source_files
from analysis_engine.parser.models import FileStructure, FunctionInfo
from analysis_engine.parser.structure import extract_structure
from analysis_engine.parser.treesitter_parser import detect_language, nodes_of_types, parse_tree

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
            or name in ("tests.py", "test.py", "conftest.py") or ".test." in name or ".spec." in name)


class Project:
    """All files of a repo plus shared analyses.

    Parse trees are large, so only the last few are kept (`tree_cache_size`). Code that works file by file,
    as the analyzers do, parses each file once; trees are rebuilt on demand if needed again.
    """

    def __init__(self, files: list, sources: dict, tree_cache_size: int = 2):
        self.files = sorted(files, key=lambda f: f.file_path)
        self.sources = sources
        self.file_map = {f.file_path: f for f in self.files}
        self.tree_cache_size = tree_cache_size
        self._trees: OrderedDict = OrderedDict()
        self._func_nodes: dict = {}
        self._lines: dict = {}
        self._resolver: Optional[CallResolver] = None
        self._call_graph = None

    # -- construction --------------------------------------------------
    @classmethod
    def from_sources(cls, sources: dict, progress=None) -> "Project":
        """`progress(stage, done, total)` is called as files are read ("parse")."""
        files, kept = [], {}
        for i, (path, text) in enumerate(sources.items(), 1):
            language = detect_language(path, text)
            if language is not None:
                files.append(extract_structure(text, language, path))
                kept[path] = text
            if progress:
                progress("parse", i, len(sources))
        return cls(files, kept)

    @classmethod
    def from_root(cls, root, progress=None) -> "Project":
        root = Path(root)
        sources = {}
        for path, _language in iter_source_files(root):
            sources[path.relative_to(root).as_posix()] = path.read_bytes().decode("utf-8-sig", errors="replace")
        return cls.from_sources(sources, progress)

    # -- incremental updates -------------------------------------------
    def update_source(self, path: str, source: Optional[str]) -> None:
        """Replace one file's content (or remove it with source=None). Only that file is re-extracted."""
        self.invalidate_graphs()
        self._drop_file_caches(path)
        language = detect_language(path, source) if source is not None else None
        if language is None:
            self.sources.pop(path, None)
            self.file_map.pop(path, None)
        else:
            self.sources[path] = source
            self.file_map[path] = extract_structure(source, language, path)
        self.files = sorted(self.file_map.values(), key=lambda f: f.file_path)

    def invalidate_graphs(self) -> None:
        self._resolver = None
        self._call_graph = None

    def _drop_file_caches(self, path: str) -> None:
        self._trees.pop(path, None)
        self._func_nodes.pop(path, None)
        self._lines.pop(path, None)

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
        if path in self._trees:
            self._trees.move_to_end(path)
            return self._trees[path]
        tree = parse_tree(self.sources[path], self.file_map[path].language)
        self._trees[path] = tree
        while len(self._trees) > self.tree_cache_size:
            evicted, _ = self._trees.popitem(last=False)
            self._func_nodes.pop(evicted, None)  # these nodes belong to the evicted tree
        return tree

    def function_nodes(self, path: str) -> dict:
        """(start_line, end_line) -> Tree-Sitter node, for every function-like node in the file."""
        tree = self.tree(path)  # also keeps `tree` alive while its nodes are cached
        if path not in self._func_nodes:
            nodes: dict = {}
            language = self.file_map[path].language
            for n in nodes_of_types(tree, language, sorted(FUNC_TYPES.get(language, ()))):
                nodes.setdefault((n.start_point[0] + 1, n.end_point[0] + 1), n)
            self._func_nodes[path] = nodes
        return self._func_nodes[path]

    def function_node(self, path: str, fn: FunctionInfo):
        return self.function_nodes(path).get((fn.start_line, fn.end_line))

    def lines(self, path: str) -> list:
        if path not in self._lines:
            self._lines[path] = self.sources[path].splitlines()
        return self._lines[path]

    def release_trees(self) -> None:
        self._trees.clear()
        self._func_nodes.clear()

    def is_entry_point(self, path: str, qualified_name: str) -> bool:
        """A function nobody in the repo calls: its parameters may carry outside input."""
        nid = f"{path}::{qualified_name}"
        g = self.call_graph
        return nid in g and g.in_degree(nid) == 0
