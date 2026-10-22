"""Call graph: who calls whom, inside a file and across files.

Nodes are functions/methods (id "path/to/file.py::Class.method"). Classes appear
only when instantiated and they have no explicit constructor. An edge A -> B
means A contains a call that resolves to B.

Resolution is static and name-based (no type inference), so calls on variables,
like `obj.method()`, stay unresolved. They are counted, not guessed.
"""
import builtins
from collections import Counter, deque
from typing import Optional

import networkx as nx

from analysis_engine.graph.resolve import ModuleIndex, build_bindings
from analysis_engine.parser.models import FileStructure

PY_BUILTINS = set(dir(builtins))
JS_GLOBALS = {
    "console", "Math", "JSON", "Object", "Array", "String", "Number", "Boolean", "Promise",
    "Date", "Error", "Map", "Set", "Symbol", "RegExp", "process", "window", "document",
    "parseInt", "parseFloat", "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "Buffer", "fetch", "isNaN", "encodeURIComponent", "decodeURIComponent", "super", "require",
}
CONSTRUCTOR = {"python": "__init__", "javascript": "constructor"}
SELF_NAMES = {"self", "cls", "this"}
MODULE_NODE = "<module>"


def node_id(path: str, qualified_name: str) -> str:
    return f"{path}::{qualified_name}"


class _Resolver:
    def __init__(self, files: list[FileStructure]):
        self.files = {f.file_path: f for f in files}
        index = ModuleIndex(files)
        self.funcs: dict[str, dict] = {}
        self.classes: dict[str, dict] = {}
        self.bindings = {}
        for f in files:
            fd: dict = {}
            for fn in f.functions:
                fd.setdefault(fn.qualified_name, fn)
            cd: dict = {}
            for c in f.classes:
                cd.setdefault(c.qualified_name, c)
            self.funcs[f.file_path] = fd
            self.classes[f.file_path] = cd
            self.bindings[f.file_path] = build_bindings(index, f)

    # -- lookups -------------------------------------------------------
    def lookup(self, path: str, name: str, depth: int = 0):
        """Resolve a plain name in a file's namespace (defined here, or imported)."""
        if name in self.funcs[path]:
            return ("function", path, name)
        if name in self.classes[path]:
            return ("class", path, name)
        if depth >= 6:
            return None
        b = self.bindings[path]
        if name in b.symbols:
            target, imported = b.symbols[name]
            if (target, imported) != (path, name):  # follow re-exports
                return self.lookup(target, imported, depth + 1)
        if name in b.modules:
            return ("module", b.modules[name])
        if name in b.external:
            return ("external",)
        return None

    def find_method(self, path: str, class_qn: str, method: str, depth: int = 0):
        qn = f"{class_qn}.{method}"
        if qn in self.funcs[path]:
            return ("function", path, qn)
        cls = self.classes[path].get(class_qn)
        if cls is None or depth >= 5:
            return None
        for base in cls.bases:  # inherited methods
            ent = self.entity(path, base)
            if ent and ent[0] == "class":
                found = self.find_method(ent[1], ent[2], method, depth + 1)
                if found:
                    return found
        return None

    def entity(self, path: str, dotted: str):
        """Resolve a dotted name like `core.Engine.start` to what it refers to."""
        parts = dotted.split(".")
        b = self.bindings[path]
        cur, i = None, 1
        for k in range(len(parts), 0, -1):  # longest imported-module prefix first
            prefix = ".".join(parts[:k])
            if prefix in b.modules:
                cur, i = ("module", b.modules[prefix]), k
                break
        if cur is None:
            cur = self.lookup(path, parts[0])
            if cur is None and parts[0] in b.external:
                cur = ("external",)
            if cur is None:
                return None
        for part in parts[i:]:
            kind = cur[0]
            if kind == "external":
                return cur
            if kind == "module":
                cur = self.lookup(cur[1], part)
            elif kind == "class":
                nested = f"{cur[2]}.{part}"
                found = self.find_method(cur[1], cur[2], part)
                if found is None and nested in self.classes[cur[1]]:
                    found = ("class", cur[1], nested)
                cur = found
            else:
                return None
            if cur is None:
                return None
        return cur

    def enclosing_class(self, path: str, caller_qn: str) -> Optional[str]:
        parts = caller_qn.split(".") if caller_qn else []
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in self.classes[path]:
                return prefix
        return None

    def local_function(self, path: str, caller_qn: str, name: str) -> Optional[str]:
        """A bare name can refer to a function nested in the caller, or a module-level one."""
        parts = caller_qn.split(".") if caller_qn else []
        for i in range(len(parts), -1, -1):
            if i > 0 and ".".join(parts[:i]) in self.classes[path]:
                continue  # class scope is skipped by bare-name lookup
            qn = ".".join(parts[:i] + [name])
            if qn in self.funcs[path]:
                return qn
        return None

    # -- public --------------------------------------------------------
    def resolve_call(self, path: str, caller_qn: str, name: str):
        """Return ("function"|"class", file, qualified_name), ("external",), ("builtin",) or None."""
        parts = name.split(".")
        language = self.files[path].language
        if parts[0] in SELF_NAMES and len(parts) == 2:
            cq = self.enclosing_class(path, caller_qn)
            return self.find_method(path, cq, parts[1]) if cq else None
        if len(parts) == 1:
            local = self.local_function(path, caller_qn, parts[0])
            if local:
                return ("function", path, local)
        ent = self.entity(path, name)
        if ent is not None:
            return ent
        builtin_names = PY_BUILTINS if language == "python" else JS_GLOBALS
        return ("builtin",) if parts[0] in builtin_names else None

    def constructor(self, path: str, class_qn: str):
        language = self.files[path].language
        return self.find_method(path, class_qn, CONSTRUCTOR.get(language, "__init__"))


def _add_edge(graph: nx.DiGraph, a: str, b: str, line: int) -> None:
    if graph.has_edge(a, b):
        graph[a][b]["count"] += 1
        graph[a][b]["lines"].append(line)
    else:
        graph.add_edge(a, b, count=1, lines=[line])


def build_call_graph(files: list[FileStructure]) -> nx.DiGraph:
    resolver = _Resolver(files)
    graph = nx.DiGraph()
    stats: Counter = Counter()

    for f in files:
        for fn in f.functions:
            nid = node_id(f.file_path, fn.qualified_name)
            if nid not in graph:
                graph.add_node(nid, file=f.file_path, name=fn.qualified_name, label=fn.qualified_name,
                               kind=fn.kind, language=f.language, start_line=fn.start_line,
                               end_line=fn.end_line, unresolved=[])

    def ensure_class_node(path: str, class_qn: str) -> str:
        nid = node_id(path, class_qn)
        if nid not in graph:
            cls = resolver.classes[path][class_qn]
            graph.add_node(nid, file=path, name=class_qn, label=class_qn, kind="class",
                           language=resolver.files[path].language, start_line=cls.start_line,
                           end_line=cls.end_line, unresolved=[])
        return nid

    def ensure_module_node(path: str) -> str:
        nid = node_id(path, MODULE_NODE)
        if nid not in graph:
            graph.add_node(nid, file=path, name=MODULE_NODE, label=f"{path} (module level)", kind="module",
                           language=resolver.files[path].language, start_line=1, end_line=1, unresolved=[])
        return nid

    for f in files:
        sites = [(fn.qualified_name, fn.calls) for fn in f.functions] + [("", f.module_calls)]
        for caller_qn, calls in sites:
            for call in calls:
                stats["calls_total"] += 1
                res = resolver.resolve_call(f.file_path, caller_qn, call.name)
                if res is None:
                    stats["unresolved"] += 1
                    if caller_qn:
                        bucket = graph.nodes[node_id(f.file_path, caller_qn)]["unresolved"]
                        if call.name not in bucket and len(bucket) < 25:
                            bucket.append(call.name)
                    continue
                kind = res[0]
                if kind in ("external", "builtin"):
                    stats[kind] += 1
                    continue
                if kind == "module":
                    stats["ignored"] += 1
                    continue
                if kind == "class":
                    ctor = resolver.constructor(res[1], res[2])
                    res = ctor if ctor else res
                target = ensure_class_node(res[1], res[2]) if res[0] == "class" else node_id(res[1], res[2])
                if target not in graph:
                    stats["unresolved"] += 1
                    continue
                caller = node_id(f.file_path, caller_qn) if caller_qn else ensure_module_node(f.file_path)
                _add_edge(graph, caller, target, call.line)
                stats["resolved"] += 1

    internal = stats["resolved"] + stats["unresolved"]
    graph.graph["stats"] = {
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "calls_total": stats["calls_total"],
        "resolved": stats["resolved"],
        "external": stats["external"],
        "builtin": stats["builtin"],
        "unresolved": stats["unresolved"],
        "resolution_rate": round(stats["resolved"] / internal, 3) if internal else None,
    }
    return graph


# ---------------------------------------------------------------- queries
def find_nodes(graph: nx.DiGraph, query: str) -> list[str]:
    """Node ids matching a full id, a qualified name ("Db.get"), or a name suffix ("get")."""
    if query in graph:
        return [query]
    exact = [n for n, d in graph.nodes(data=True) if d.get("name") == query]
    if exact:
        return sorted(exact)
    return sorted(n for n, d in graph.nodes(data=True) if d.get("name", "").endswith("." + query))


def _reach(graph: nx.DiGraph, node: str, depth: int, forward: bool) -> list[str]:
    seen = {node}
    out: list[str] = []
    queue = deque([(node, 0)])
    while queue:
        current, d = queue.popleft()
        if d == depth:
            continue
        for nxt in (graph.successors(current) if forward else graph.predecessors(current)):
            if nxt not in seen:
                seen.add(nxt)
                out.append(nxt)
                queue.append((nxt, d + 1))
    return sorted(out)


def callees(graph: nx.DiGraph, node: str, depth: int = 1) -> list[str]:
    """Functions called by `node`, directly (depth 1) or transitively."""
    return _reach(graph, node, depth, forward=True)


def callers(graph: nx.DiGraph, node: str, depth: int = 1) -> list[str]:
    """Functions that call `node`, directly (depth 1) or transitively."""
    return _reach(graph, node, depth, forward=False)
