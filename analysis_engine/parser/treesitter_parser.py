"""Tree-Sitter based parser for Python and JavaScript.

Returns the same kind of data as python_parser.parse_python (functions,
classes, imports, line ranges, parse_error) so it can be swapped in later.
"""
from dataclasses import dataclass, field
from typing import Optional

import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
from tree_sitter import Language, Parser

_LANGUAGES = {
    "python": Language(tspy.language()),
    "javascript": Language(tsjs.language()),
}
_PARSERS = {name: Parser(lang) for name, lang in _LANGUAGES.items()}

EXT_TO_LANGUAGE = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript"}


@dataclass
class ParsedCode:
    language: str
    tree: object = None
    functions: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    line_ranges: dict[str, tuple[int, int]] = field(default_factory=dict)
    parse_error: Optional[str] = None


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _lines(node) -> tuple[int, int]:
    return node.start_point[0] + 1, node.end_point[0] + 1


def _first_error_line(node) -> Optional[int]:
    if node.type == "ERROR" or node.is_missing:
        return node.start_point[0] + 1
    for child in node.children:
        if child.has_error or child.is_missing:
            line = _first_error_line(child)
            if line:
                return line
    return None


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _extract_python(root, out: ParsedCode) -> None:
    for node in _walk(root):
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
    for node in _walk(root):
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
    if language not in _PARSERS:
        return ParsedCode(language=language, parse_error=f"unsupported language: {language}")
    tree = _PARSERS[language].parse(source.encode("utf-8"))
    out = ParsedCode(language=language, tree=tree)
    if tree.root_node.has_error:
        out.parse_error = f"line {_first_error_line(tree.root_node) or 1}: syntax error"
    if language == "python":
        _extract_python(tree.root_node, out)
    else:
        _extract_javascript(tree.root_node, out)
    out.functions = sorted(set(out.functions))
    out.classes = sorted(set(out.classes))
    out.imports = sorted(set(out.imports))
    return out
