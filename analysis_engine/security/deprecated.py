"""Deprecated / removed API detector (reported as CWE-477, use of obsolete function)."""
import hashlib
from typing import Optional

from analysis_engine.parser.treesitter_parser import nodes_of_types
from analysis_engine.project import Project
from analysis_engine.security.aliases import build_alias_map, canonical_name
from analysis_engine.security.rule_loader import DeprecatedItem, DeprecatedRules, load_deprecated_rules
from shared.schemas import Finding, LineRange, Severity

DOTTED_NODES = {"attribute", "member_expression"}


def _matches(item: DeprecatedItem, raw: str, canon: str) -> bool:
    if item.match.startswith("."):
        return raw.endswith(item.match) or canon.endswith(item.match)
    return item.match in (raw, canon)


def _finding(path: str, line: int, code: str, item: DeprecatedItem) -> Finding:
    status = f"removed in {item.removed}" if item.removed else f"deprecated since {item.since}"
    name = item.match.lstrip(".")
    digest = hashlib.sha1(f"CWE-477|{path}|{line}|{item.match}".encode()).hexdigest()[:8]
    return Finding(
        finding_id=f"CWE-477-{digest}", cwe_id="CWE-477", severity=Severity.HIGH if item.removed else Severity.LOW,
        confidence=0.9, message=f"Deprecated API: {name}",
        explanation=f"{name} is {status}. Replacement: {item.replacement}.",
        file_path=path, line_number=line, line_range=LineRange(start=line, end=line), evidence=code,
        source="deprecated-api", suggested_remediation=f"Replace {name} with {item.replacement}.")


def find_deprecated_apis(project: Project, rules: Optional[DeprecatedRules] = None, paths=None) -> list:
    rules = rules or load_deprecated_rules()
    out: dict = {}
    for path in (sorted(project.file_map) if paths is None else [p for p in paths if p in project.file_map]):
        f = project.file_map[path]
        items = rules.languages.get(f.language, [])
        if not items:
            continue
        lines = project.lines(path)
        aliases = build_alias_map(f)
        code = lambda n: lines[n - 1].strip() if 0 < n <= len(lines) else ""  # noqa: E731

        def hit(line: int, item: DeprecatedItem) -> None:
            out.setdefault((path, line, item.match), _finding(path, line, code(line), item))

        for imp in f.imports:  # modules
            for item in (i for i in items if i.kind == "module"):
                if imp.module == item.match or imp.module.startswith(item.match + "."):
                    hit(imp.line, item)
        call_items = [i for i in items if i.kind == "call"]
        sites = [c for fn in f.functions for c in fn.calls] + f.module_calls
        for call in sites:  # calls
            canon = canonical_name(call.name, aliases)
            for item in call_items:
                if _matches(item, call.name, canon):
                    hit(call.line, item)
        attr_items = [i for i in items if i.kind == "attribute"]
        text = project.sources[path]
        if attr_items and any(i.match.rsplit(".", 1)[-1] in text for i in attr_items):  # cheap precheck
            for node in nodes_of_types(project.tree(path), f.language, tuple(DOTTED_NODES)):  # non-call references
                raw = node.text.decode("utf-8", errors="replace")
                canon = canonical_name(raw, aliases)
                for item in attr_items:
                    if item.match in (raw, canon):
                        hit(node.start_point[0] + 1, item)
    return sorted(out.values(), key=lambda x: (x.file_path, x.line_number, x.finding_id))
