from shared.schemas import ContextPackage

def build_context_package(target_function: str, functions: list[str], imports: list[str], source: str) -> ContextPackage:
    """Starter context packager. Call graph/taint analysis are extension points."""
    return ContextPackage(
        target_function=target_function,
        callers=[],
        callees=[],
        imports=imports,
        taint_path=[],
        token_trimmed_context=source[:4000],
    )
