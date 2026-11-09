"""Tree-Sitter parsing for Python, JavaScript and (parse-only) Java.

parse_code() returns simple name lists. For full structure (docstrings,
params, methods) use analysis_engine.parser.structure.extract_structure().
"""
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
from tree_sitter import Language, Parser, Query

try:  # tree-sitter >= 0.25 runs queries through a cursor object
    from tree_sitter import QueryCursor
except ImportError:  # pragma: no cover - older releases
    QueryCursor = None

_LANGUAGES = {
    "python": Language(tspy.language()),
    "javascript": Language(tsjs.language()),
}
try:  # Java is optional: a missing package must not break Python/JS parsing
    import tree_sitter_java as tsjava

    _LANGUAGES["java"] = Language(tsjava.language())
except ImportError:  # pragma: no cover
    pass

_local = threading.local()      # a Tree-Sitter Parser must not be shared between threads, so each thread gets its own
_query_lock = threading.Lock()


def _parser_for(language: str) -> Optional[Parser]:
    parsers = getattr(_local, "parsers", None)
    if parsers is None:
        parsers = _local.parsers = {}
    if language not in parsers and language in _LANGUAGES:
        parsers[language] = Parser(_LANGUAGES[language])
    return parsers.get(language)

EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".java": "java",
}


@dataclass
class ParsedCode:
    language: str
    tree: object = None
    functions: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    line_ranges: dict[str, tuple[int, int]] = field(default_factory=dict)
    parse_error: Optional[str] = None


def detect_language(path: str, source: Optional[str] = None) -> Optional[str]:
    """Language from file extension, falling back to a shebang line."""
    language = EXT_TO_LANGUAGE.get(Path(path).suffix.lower())
    if language:
        return language
    if source and source.startswith("#!"):
        first_line = source.split("\n", 1)[0]
        if "python" in first_line:
            return "python"
        if "node" in first_line:
            return "javascript"
    return None


def parse_tree(source: str, language: str):
    """Return a Tree-Sitter tree, or None if the language is not available."""
    parser = _parser_for(language)
    return parser.parse(source.encode("utf-8")) if parser else None


_QUERIES: dict = {}


def node_query(language: str, types) -> Optional[object]:
    """A compiled query matching every node whose type is in `types` (types the grammar lacks are skipped)."""
    key = (language, tuple(types))
    with _query_lock:
        if key not in _QUERIES:
            _QUERIES[key] = _compile_query(language, types)
    return _QUERIES[key]


def _compile_query(language: str, types) -> Optional[object]:
    lang = _LANGUAGES.get(language)
    # the method was renamed between releases (id_for_node_type -> id_for_node_kind)
    lookup = getattr(lang, "id_for_node_kind", None) or getattr(lang, "id_for_node_type", None)
    valid = [t for t in types if lang is not None and (lookup is None or lookup(t, True))]
    if not valid:
        return None
    source = "[" + " ".join(f"({t})" for t in valid) + "] @n"
    try:
        return Query(lang, source)
    except TypeError:  # pragma: no cover - older releases
        return lang.query(source)


def nodes_of_types(tree, language: str, types) -> list:
    """All nodes of the given types, in document order (parents before children). Runs inside Tree-Sitter."""
    query = node_query(language, types)
    if query is None or tree is None:
        return []
    caps = QueryCursor(query).captures(tree.root_node) if QueryCursor else query.captures(tree.root_node)
    nodes = caps.get("n", []) if isinstance(caps, dict) else [n for n, _ in caps]
    return sorted(nodes, key=lambda n: (n.start_byte, -n.end_byte))


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _lines(node) -> tuple[int, int]:
    return node.start_point[0] + 1, node.end_point[0] + 1


def walk(node):
    """Iterative depth-first walk in document order (safe on deep trees)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def first_error_line(root) -> Optional[int]:
    for node in walk(root):
        if node.type == "ERROR" or node.is_missing:
            return node.start_point[0] + 1
    return None


def _extract_python(root, out: ParsedCode) -> None:
    for node in walk(root):
        if node.type == "function_definition":
            name = _text(node.child_by_field_name("name"))
            out.functions.append(name)
            out.line_ranges[name] = _lines(node)
        elif node.type == "class_definition":
            name = _text(node.child_by_field_name("name"))
            out.classes.append(name)
            out.line_ranges[name] = _lines(node)
        elif node.type == "import_statement":
            for n in node.children_by_field_name("name"):
                target = n.child_by_field_name("name") if n.type == "aliased_import" else n
                out.imports.append(_text(target))
        elif node.type == "import_from_statement":
            module = node.child_by_field_name("module_name")
            out.imports.append(_text(module) if module else "")


def _extract_javascript(root, out: ParsedCode) -> None:
    for node in walk(root):
        if node.type in ("function_declaration", "generator_function_declaration", "method_definition"):
            name_node = node.child_by_field_name("name")
            if name_node:
                name = _text(name_node)
                out.functions.append(name)
                out.line_ranges[name] = _lines(node)
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in ("arrow_function", "function_expression", "function"):
                name = _text(node.child_by_field_name("name"))
                out.functions.append(name)
                out.line_ranges[name] = _lines(node)
        elif node.type == "class_declaration":
            name = _text(node.child_by_field_name("name"))
            out.classes.append(name)
            out.line_ranges[name] = _lines(node)
        elif node.type == "import_statement":
            source = node.child_by_field_name("source")
            if source is not None:
                out.imports.append(_text(source).strip("'\""))
        elif node.type == "call_expression":  # require("x")
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is not None and _text(fn) == "require" and args is not None and args.named_child_count:
                first = args.named_children[0]
                if first.type == "string":
                    out.imports.append(_text(first).strip("'\""))


def parse_code(source: str, language: str) -> ParsedCode:
    """Parse source text. Never raises on bad code; sets parse_error instead."""
    tree = parse_tree(source, language)
    if tree is None:
        return ParsedCode(language=language, parse_error=f"unsupported language: {language}")
    out = ParsedCode(language=language, tree=tree)
    if tree.root_node.has_error:
        out.parse_error = f"line {first_error_line(tree.root_node) or 1}: syntax error"
    if language == "python":
        _extract_python(tree.root_node, out)
    elif language == "javascript":
        _extract_javascript(tree.root_node, out)
    # java: parse only (stub), no extraction yet
    out.functions = sorted(set(out.functions))
    out.classes = sorted(set(out.classes))
    out.imports = sorted(set(out.imports))
    return out
