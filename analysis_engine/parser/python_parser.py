import ast
from dataclasses import dataclass
from typing import Optional

@dataclass
class ParsedPython:
    tree: Optional[ast.AST]
    functions: list[str]
    classes: list[str]
    imports: list[str]
    line_ranges: dict[str, tuple[int, int]]
    parse_error: Optional[str] = None

def parse_python(source: str) -> ParsedPython:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return ParsedPython(None, [], [], [], {}, f"line {exc.lineno}: {exc.msg}")
    functions, classes, imports, line_ranges = [], [], [], {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
            end = getattr(node, "end_lineno", node.lineno)
            line_ranges[node.name] = (node.lineno, end)
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
            end = getattr(node, "end_lineno", node.lineno)
            line_ranges[node.name] = (node.lineno, end)
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return ParsedPython(tree, sorted(functions), sorted(classes), sorted(set(imports)), line_ranges)
