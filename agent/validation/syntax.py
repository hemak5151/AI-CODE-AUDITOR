import ast

def validate_python_syntax(source: str) -> tuple[bool, str | None]:
    try: ast.parse(source); return True, None
    except SyntaxError as exc: return False, f"line {exc.lineno}: {exc.msg}"
