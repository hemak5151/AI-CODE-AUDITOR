import ast
from shared.schemas import Finding, Severity, LineRange

RULES = {
    "python-eval": ("CWE-95", Severity.HIGH),
    "python-exec": ("CWE-95", Severity.HIGH),
    "shell-true": ("CWE-78", Severity.HIGH),
    "hardcoded-secret": ("CWE-798", Severity.MEDIUM),
}

def _finding(fid, cwe, sev, msg, expl, line, evidence, remediation):
    return Finding(
        finding_id=fid, cwe_id=cwe, severity=sev, confidence=0.95,
        message=msg, explanation=expl, file_path="submitted.py", line_number=line,
        line_range=LineRange(start=line, end=line), evidence=evidence, source="deterministic-ast",
        suggested_remediation=remediation,
    )

def scan_python(tree: ast.AST, source: str) -> list[Finding]:
    findings=[]
    lines=source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            name=node.func.id
            cwe, sev=RULES[f"python-{name}"]
            findings.append(_finding(f"{name}-{node.lineno}", cwe, sev, f"Use of {name}()", f"{name}() executes dynamically supplied Python code and can enable code execution when input is untrusted.", node.lineno, lines[node.lineno-1].strip(), f"Avoid {name}(); use a safe parser or explicit dispatch."))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(_finding(f"shell-true-{node.lineno}", "CWE-78", Severity.HIGH, "subprocess.run(..., shell=True)", "A shell command is executed through a shell, increasing command-injection risk when command data is influenced by users.", node.lineno, lines[node.lineno-1].strip(), "Prefer argument lists with shell=False and validate untrusted input."))
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and any(x in target.id.lower() for x in ("password", "secret", "api_key", "token")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
                        findings.append(_finding(f"secret-{node.lineno}", "CWE-798", Severity.MEDIUM, "Possible hardcoded secret", "A credential-like variable is assigned a literal string.", node.lineno, lines[node.lineno-1].strip(), "Load secrets from environment variables or a secret manager."))
    return findings
