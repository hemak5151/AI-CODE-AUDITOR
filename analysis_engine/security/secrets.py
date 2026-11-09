"""Hardcoded secrets (CWE-798): credential-looking names assigned literal strings, plus
well-known token formats. Secret values are masked in findings so reports never leak them."""
import hashlib
import re
from typing import Optional

from analysis_engine.parser.treesitter_parser import nodes_of_types
from analysis_engine.project import Project, is_test_or_example_path
from analysis_engine.security.rule_loader import TaintRules, load_taint_rules
from shared.schemas import Finding, LineRange, Severity

TOKEN_FORMATS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
]
SKIP_VALUE = re.compile(r"^(\$\{.*\}|\{\{.*\}\}|<.*>|%\(.*\)s|\$[A-Z_]+)$")
TEMPLATE = re.compile(r"%\(|%[sd]|\{[^}]*\}")
STRING_NODES = {"string", "template_string"}
PAIRS = {"python": ("assignment", "keyword_argument", "pair"),
         "javascript": ("variable_declarator", "assignment_expression", "pair")}


def _literal(node) -> Optional[str]:
    """Contents of a plain string literal (no interpolation), else None."""
    if node is None or node.type not in STRING_NODES:
        return None
    if any(c.type in ("interpolation", "template_substitution") for c in node.children):
        return None
    text = node.text.decode("utf-8", errors="replace")
    m = re.match(r"^[rbuf]*('''|\"\"\"|'|\"|`)(.*)\1$", text, re.S | re.I)
    return m.group(2) if m else None


def _last_name(node) -> Optional[str]:
    if node is None:
        return None
    if node.type in ("identifier", "property_identifier"):
        return node.text.decode()
    if node.type in ("attribute", "member_expression"):
        tail = node.child_by_field_name("attribute") or node.child_by_field_name("property")
        return tail.text.decode() if tail is not None else None
    if node.type == "string":
        return _literal(node)
    return None


def looks_like_secret(value: str) -> bool:
    """For weakly-named variables (e.g. `token`): only long values with mixed characters qualify."""
    if len(value) < 12 or " " in value:
        return False
    classes = sum([any(c.islower() for c in value), any(c.isupper() for c in value), any(c.isdigit() for c in value),
                   any(not c.isalnum() and c not in "_-" for c in value)])
    return classes >= 3 or (classes >= 2 and len(value) >= 20)


def _is_template_or_sentence(value: str) -> bool:
    return bool(TEMPLATE.search(value)) or value.count(" ") >= 2 or "\n" in value


def _make(file: str, line: int, label: str, severity: Severity, confidence: float, code: str, kind: str) -> Finding:
    if is_test_or_example_path(file):  # credentials in tests and examples are usually fakes
        severity = Severity.MEDIUM if severity == Severity.HIGH else Severity.LOW
        confidence = round(confidence * 0.6, 2) if confidence > 0.9 else 0.4
    digest = hashlib.sha1(f"CWE-798|{file}|{line}|{label}".encode()).hexdigest()[:8]
    return Finding(
        finding_id=f"CWE-798-{digest}", cwe_id="CWE-798", severity=severity, confidence=confidence,
        message=f"Hardcoded secret: {label}",
        explanation=f"A {kind} is stored as a string literal in the source code. Anyone with access to the repository can read it.",
        file_path=file, line_number=line, line_range=LineRange(start=line, end=line), evidence=code,
        source="secret-scan", suggested_remediation="Load secrets from environment variables or a secret manager and rotate the exposed value.")


def find_hardcoded_secrets(project: Project, rules: Optional[TaintRules] = None, paths=None,
                           include_tests: bool = False) -> list:
    rules = rules or load_taint_rules()
    strong = [h.lower() for h in rules.secrets.name_hints]
    weak = [h.lower() for h in rules.secrets.weak_name_hints]
    ignore = [h.lower() for h in rules.secrets.name_ignore_hints]
    placeholders = {p.lower() for p in rules.secrets.placeholders}
    findings: dict = {}
    for path in (sorted(project.file_map) if paths is None else [p for p in paths if p in project.file_map]):
        f = project.file_map[path]
        pair_types = PAIRS.get(f.language)
        lines = project.lines(path)
        for n, text in enumerate(lines, 1):  # known token formats, anywhere
            for label, rx in TOKEN_FORMATS:
                if rx.search(text):
                    code = rx.sub("<redacted>", text.strip())
                    findings[(path, n)] = _make(path, n, label, Severity.HIGH, 0.95, code, "credential")
        tree = project.tree(path)
        if tree is None or pair_types is None:
            continue
        if not include_tests and is_test_or_example_path(path):
            continue  # fake credentials in tests/examples are normal; known token formats were already checked above
        for node in nodes_of_types(tree, f.language, pair_types):
            if node.type == "pair":
                name_node, value_node = node.child_by_field_name("key"), node.child_by_field_name("value")
            elif node.type == "keyword_argument":
                name_node, value_node = node.child_by_field_name("name"), node.child_by_field_name("value")
            elif node.type == "variable_declarator":
                name_node, value_node = node.child_by_field_name("name"), node.child_by_field_name("value")
            else:
                name_node, value_node = node.child_by_field_name("left"), node.child_by_field_name("right")
            name, value = _last_name(name_node), _literal(value_node)
            if not name or value is None:
                continue
            low = name.lower()
            is_strong, is_weak = any(h in low for h in strong), any(h in low for h in weak)
            if not (is_strong or is_weak) or any(i in low for i in ignore):
                continue
            if len(value) < rules.secrets.min_length or value.lower() in placeholders or SKIP_VALUE.match(value) \
                    or _is_template_or_sentence(value):
                continue
            if not is_strong and not looks_like_secret(value):
                continue
            line = node.start_point[0] + 1
            if (path, line) in findings:
                continue
            findings[(path, line)] = _make(path, line, name, Severity.MEDIUM, 0.7,
                                           f"{name} = \"<redacted {len(value)} chars>\"", "credential-like value")
    return sorted(findings.values(), key=lambda x: (x.file_path, x.line_number))
