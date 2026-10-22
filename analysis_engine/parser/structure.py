"""Structure extractor v1: functions, classes, imports, docstrings, line ranges.

    extract_structure(source, language, file_path) -> FileStructure
    extract_file(path, root)                       -> FileStructure

Never raises on bad input: problems are reported in `parse_error`.
Java is a stub (parsed, nothing extracted yet).
Line numbers are 1-based. A function's range starts at `def`/`function`
(decorators are not included).
"""
import ast
import inspect
import re
from pathlib import Path
from typing import Iterator, Optional

from analysis_engine.parser.models import CallInfo, ClassInfo, FileStructure, FunctionInfo, ImportInfo
from analysis_engine.parser.treesitter_parser import (
    detect_language,
    first_error_line,
    parse_tree,
)

# A scope is a tuple of (kind, name, info) entries,
# e.g. (("class", "Db", ClassInfo), ("function", "get", FunctionInfo))
Scope = tuple
_CALL_NAME = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")


def _record_call(out: FileStructure, scope: Scope, text: str, line: int) -> None:
    """Attach a call to the innermost enclosing function, or to the module."""
    if len(text) > 200 or not _CALL_NAME.match(text):
        return  # e.g. f().g, lambda, subscript: not a plain dotted name
    call = CallInfo(name=text, line=line)
    for kind, _name, info in reversed(scope):
        if kind == "function":
            info.calls.append(call)
            return
    out.module_calls.append(call)


def _t(node) -> str:
    return node.text.decode("utf-8", errors="replace")


def _span(node) -> tuple[int, int]:
    return node.start_point[0] + 1, node.end_point[0] + 1


def _qualified(scope: Scope, name: str) -> str:
    return ".".join([s[1] for s in scope] + [name])


def _parent_class(scope: Scope) -> Optional[str]:
    return scope[-1][1] if scope and scope[-1][0] == "class" else None


# ---------------------------------------------------------------- Python
def _py_docstring(node) -> Optional[str]:
    body = node.child_by_field_name("body")
    if body is None or not body.named_children:
        return None
    first = body.named_children[0]
    if first.type != "expression_statement" or not first.named_children:
        return None
    string = first.named_children[0]
    if string.type != "string":
        return None
    raw = _t(string)
    try:
        value = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        value = raw.strip("'\"")
    return inspect.cleandoc(value) if isinstance(value, str) else None


def _py_params(func) -> list[str]:
    params = func.child_by_field_name("parameters")
    out: list[str] = []
    if params is None:
        return out
    for p in params.named_children:
        if p.type == "identifier":
            out.append(_t(p))
        elif p.type == "typed_parameter":
            if p.named_children:
                out.append(_t(p.named_children[0]))
        elif p.type in ("default_parameter", "typed_default_parameter"):
            name = p.child_by_field_name("name")
            if name is not None:
                out.append(_t(name))
        elif p.type in ("list_splat_pattern", "dictionary_splat_pattern"):
            out.append(_t(p))
    return out


def _py_imports(node) -> Iterator[ImportInfo]:
    line = node.start_point[0] + 1
    if node.type == "import_statement":
        for n in node.children_by_field_name("name"):
            if n.type == "aliased_import":
                module = n.child_by_field_name("name")
                alias = n.child_by_field_name("alias")
                yield ImportInfo(module=_t(module), alias=_t(alias) if alias else None, line=line)
            else:
                yield ImportInfo(module=_t(n), line=line)
    else:  # import_from_statement
        module = node.child_by_field_name("module_name")
        names: list[str] = []
        local_names: dict[str, str] = {}
        for n in node.children_by_field_name("name"):
            if n.type == "aliased_import":
                imported = _t(n.child_by_field_name("name"))
                alias = n.child_by_field_name("alias")
                names.append(imported)
                if alias is not None:
                    local_names[_t(alias)] = imported
            else:
                names.append(_t(n))
        if any(c.type == "wildcard_import" for c in node.children):
            names.append("*")
        yield ImportInfo(module=_t(module) if module else "", names=names,
                         local_names=local_names, line=line)


def _extract_python(root, out: FileStructure) -> None:
    stack = [(root, ())]
    while stack:
        node, scope = stack.pop()
        new_scope = scope
        if node.type == "function_definition" and node.child_by_field_name("name") is not None:
            name = _t(node.child_by_field_name("name"))
            start, end = _span(node)
            parent = _parent_class(scope)
            info = FunctionInfo(
                name=name, qualified_name=_qualified(scope, name),
                kind="method" if parent else "function",
                start_line=start, end_line=end,
                params=_py_params(node), docstring=_py_docstring(node), parent_class=parent,
            )
            out.functions.append(info)
            new_scope = scope + (("function", name, info),)
        elif node.type == "class_definition" and node.child_by_field_name("name") is not None:
            name = _t(node.child_by_field_name("name"))
            start, end = _span(node)
            supers = node.child_by_field_name("superclasses")
            bases = [_t(c) for c in supers.named_children
                     if c.type not in ("comment", "keyword_argument")] if supers else []
            cinfo = ClassInfo(
                name=name, qualified_name=_qualified(scope, name),
                start_line=start, end_line=end, bases=bases, docstring=_py_docstring(node),
            )
            out.classes.append(cinfo)
            new_scope = scope + (("class", name, cinfo),)
        elif node.type in ("import_statement", "import_from_statement"):
            out.imports.extend(_py_imports(node))
            continue
        elif node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is not None:
                _record_call(out, scope, _t(fn), node.start_point[0] + 1)
        for child in reversed(node.children):
            stack.append((child, new_scope))


# ------------------------------------------------------------ JavaScript
_JS_WRAPPERS = ("export_statement", "lexical_declaration", "variable_declaration")
_JS_FUNCTION_VALUES = ("arrow_function", "function_expression", "function", "generator_function")


def _js_doc(node) -> Optional[str]:
    """JSDoc comment (/** ... */) directly above the declaration."""
    anchor = node
    while anchor.parent is not None and anchor.parent.type in _JS_WRAPPERS:
        anchor = anchor.parent
    prev = anchor.prev_sibling
    if prev is None or prev.type != "comment" or prev.end_point[0] < anchor.start_point[0] - 1:
        return None
    text = _t(prev)
    if not text.startswith("/**"):
        return None
    body = text[3:-2] if text.endswith("*/") else text[3:]
    lines = [re.sub(r"^\s*\*\s?", "", line).rstrip() for line in body.splitlines()]
    return "\n".join(lines).strip() or None


def _js_params(fn) -> list[str]:
    params = fn.child_by_field_name("parameters")
    if params is None:
        single = fn.child_by_field_name("parameter")
        return [_t(single)] if single is not None else []
    out = []
    for c in params.named_children:
        if c.type == "comment":
            continue
        if c.type == "assignment_pattern":
            left = c.child_by_field_name("left")
            out.append(_t(left) if left is not None else _t(c))
        else:
            out.append(_t(c))
    return out


def _js_import(node) -> Optional[ImportInfo]:
    source = node.child_by_field_name("source")
    if source is None:
        return None
    names: list[str] = []
    local_names: dict[str, str] = {}
    alias: Optional[str] = None
    for c in node.children:
        if c.type != "import_clause":
            continue
        for x in c.children:
            if x.type == "identifier":
                names.append(_t(x))  # default import (local name)
            elif x.type == "named_imports":
                for spec in x.named_children:
                    if spec.type == "import_specifier":
                        n = spec.child_by_field_name("name")
                        a = spec.child_by_field_name("alias")
                        imported = _t(n) if n is not None else _t(spec)
                        names.append(imported)
                        if a is not None:
                            local_names[_t(a)] = imported
            elif x.type == "namespace_import":
                names.append("*")
                ident = next((y for y in x.named_children if y.type == "identifier"), None)
                alias = _t(ident) if ident is not None else None
    return ImportInfo(module=_t(source).strip("'\""), names=names, alias=alias,
                      local_names=local_names, line=node.start_point[0] + 1)


def _js_require_target(call_node) -> Optional[str]:
    fn = call_node.child_by_field_name("function")
    args = call_node.child_by_field_name("arguments")
    if fn is not None and _t(fn) == "require" and args is not None and args.named_child_count:
        first = args.named_children[0]
        if first.type == "string":
            return _t(first).strip("'\"")
    return None


def _js_require_binding(declarator, value, out: FileStructure) -> None:
    """const x = require('m')  /  const { a, b } = require('m')"""
    target = _js_require_target(value)
    name_node = declarator.child_by_field_name("name")
    if target is None or name_node is None:
        return
    alias, names = None, []
    if name_node.type == "identifier":
        alias = _t(name_node)
    elif name_node.type == "object_pattern":
        for c in name_node.named_children:
            if c.type == "shorthand_property_identifier_pattern":
                names.append(_t(c))
            elif c.type == "pair_pattern":
                key = c.child_by_field_name("key")
                if key is not None:
                    names.append(_t(key))
    out.imports.append(ImportInfo(module=target, names=names, alias=alias,
                                  line=declarator.start_point[0] + 1))


def _extract_javascript(root, out: FileStructure) -> None:
    stack = [(root, ())]
    while stack:
        node, scope = stack.pop()
        new_scope = scope
        t = node.type
        if t in ("function_declaration", "generator_function_declaration", "method_definition") \
                and node.child_by_field_name("name") is not None:
            name = _t(node.child_by_field_name("name"))
            start, end = _span(node)
            info = FunctionInfo(
                name=name, qualified_name=_qualified(scope, name),
                kind="method" if t == "method_definition" else "function",
                start_line=start, end_line=end, params=_js_params(node),
                docstring=_js_doc(node), parent_class=_parent_class(scope),
            )
            out.functions.append(info)
            new_scope = scope + (("function", name, info),)
        elif t == "variable_declarator":
            value = node.child_by_field_name("value")
            name_node = node.child_by_field_name("name")
            if value is not None and name_node is not None and name_node.type == "identifier" \
                    and value.type in _JS_FUNCTION_VALUES:
                name = _t(name_node)
                start, end = _span(node)
                info = FunctionInfo(
                    name=name, qualified_name=_qualified(scope, name), kind="function",
                    start_line=start, end_line=end, params=_js_params(value),
                    docstring=_js_doc(node), parent_class=_parent_class(scope),
                )
                out.functions.append(info)
                new_scope = scope + (("function", name, info),)
            elif value is not None and value.type == "call_expression":
                _js_require_binding(node, value, out)
        elif t == "class_declaration" and node.child_by_field_name("name") is not None:
            name = _t(node.child_by_field_name("name"))
            start, end = _span(node)
            bases = []
            for c in node.children:
                if c.type == "class_heritage" and c.named_children:
                    bases.append(_t(c.named_children[0]))
            cinfo = ClassInfo(
                name=name, qualified_name=_qualified(scope, name),
                start_line=start, end_line=end, bases=bases, docstring=_js_doc(node),
            )
            out.classes.append(cinfo)
            new_scope = scope + (("class", name, cinfo),)
        elif t == "import_statement":
            info = _js_import(node)
            if info:
                out.imports.append(info)
            continue
        elif t == "call_expression":
            target = _js_require_target(node)
            if target is not None:
                parent = node.parent
                bound = False
                if parent is not None and parent.type == "variable_declarator":
                    v = parent.child_by_field_name("value")
                    bound = v is not None and v.id == node.id  # already recorded with its names
                if not bound:
                    out.imports.append(ImportInfo(module=target, line=node.start_point[0] + 1))
            else:
                fn = node.child_by_field_name("function")
                if fn is not None:
                    _record_call(out, scope, _t(fn), node.start_point[0] + 1)
        elif t == "new_expression":
            ctor = node.child_by_field_name("constructor")
            if ctor is not None:
                _record_call(out, scope, _t(ctor), node.start_point[0] + 1)
        for child in reversed(node.children):
            stack.append((child, new_scope))


# ---------------------------------------------------------------- public API
def extract_structure(source: str, language: Optional[str], file_path: str = "") -> FileStructure:
    """Extract normalized structure from source text. Never raises on bad code."""
    if language is None:
        return FileStructure(file_path=file_path, language="unknown", parse_error="unsupported language: unknown")
    tree = parse_tree(source, language)
    if tree is None:
        return FileStructure(file_path=file_path, language=language,
                             parse_error=f"unsupported language: {language}")
    out = FileStructure(file_path=file_path, language=language)
    root = tree.root_node
    if root.has_error:
        out.parse_error = f"line {first_error_line(root) or 1}: syntax error"
    if language == "python":
        _extract_python(root, out)
    elif language == "javascript":
        _extract_javascript(root, out)
    # java: stub, parse only

    out.functions.sort(key=lambda f: (f.start_line, f.qualified_name))
    out.classes.sort(key=lambda c: (c.start_line, c.qualified_name))
    out.imports.sort(key=lambda i: (i.line, i.module))
    for cls in out.classes:
        cls.methods = [f.name for f in out.functions
                       if f.parent_class == cls.name and f.qualified_name == f"{cls.qualified_name}.{f.name}"]
    return out


def extract_file(path, root=None) -> FileStructure:
    """Read a file and extract its structure. Unreadable files give a parse_error."""
    p = Path(path)
    rel = p.relative_to(root).as_posix() if root is not None else p.as_posix()
    try:
        source = p.read_bytes().decode("utf-8-sig", errors="replace")
    except OSError as exc:
        return FileStructure(file_path=rel, language=detect_language(rel) or "unknown",
                             parse_error=f"could not read file: {exc}")
    return extract_structure(source, detect_language(rel, source), rel)
