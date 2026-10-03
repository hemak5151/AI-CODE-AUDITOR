from shared.schemas import AnalysisResult
from .parser import parse_python
from .security import scan_python
from .context import build_context_package

def analyze_python(source: str) -> AnalysisResult:
    parsed=parse_python(source)
    if parsed.parse_error:
        return AnalysisResult(findings=[], parse_error=parsed.parse_error)
    findings=scan_python(parsed.tree, source)
    target=parsed.functions[0] if parsed.functions else "module"
    context=build_context_package(target, parsed.functions, parsed.imports, source)
    return AnalysisResult(findings=findings, functions=parsed.functions, classes=parsed.classes, imports=parsed.imports, context=context)
