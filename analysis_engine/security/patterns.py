"""Risky calls: dangerous functions called with a non-constant argument (reported without a proven data flow).

`eval(x)` and `os.system(cmd)` are dangerous even when we cannot show where `x` or `cmd` came from. These are
pattern findings, so their confidence is lower than a proven taint flow; the taint engine's finding replaces them
when both apply to the same line. Which CWEs get this treatment is set in rule_data/taint.yaml.
"""
import hashlib
from typing import Optional

from analysis_engine.parser.treesitter_parser import nodes_of_types
from analysis_engine.project import Project
from analysis_engine.security.aliases import build_alias_map, canonical_name
from analysis_engine.security.rule_loader import TaintRules, load_taint_rules
from analysis_engine.security.taint import CALLS, TaintAnalyzer, _dotted, _name_matches
from shared.schemas import Finding, LineRange, Severity

LITERAL_LEAVES = {"integer", "float", "true", "false", "none", "number", "null", "True", "False"}
COMBINERS = {"binary_operator", "binary_expression", "parenthesized_expression", "concatenated_string"}


def is_constant(node) -> bool:
    """A literal, or literals joined together. An f-string or template with substitutions is not constant."""
    if node.type in ("string", "template_string"):
        return not any(c.type in ("interpolation", "template_substitution") for c in node.children)
    if node.type in LITERAL_LEAVES:
        return True
    if node.type in COMBINERS:
        return all(is_constant(c) for c in node.named_children if c.type != "comment")
    return False


def _arguments(call) -> tuple:
    args_node = call.child_by_field_name("arguments")
    positional, keywords = [], {}
    if args_node is not None:
        for c in args_node.named_children:
            if c.type == "comment":
                continue
            if c.type == "keyword_argument":
                name, value = c.child_by_field_name("name"), c.child_by_field_name("value")
                if name is not None and value is not None:
                    keywords[name.text.decode()] = value
            else:
                positional.append(c)
    return positional, keywords


def find_risky_patterns(project: Project, rules: Optional[TaintRules] = None, paths=None) -> list:
    rules = rules or load_taint_rules()
    if not rules.risky_call_cwes:
        return []
    out: dict = {}
    for path in (sorted(project.file_map) if paths is None else [p for p in paths if p in project.file_map]):
        f = project.file_map[path]
        lang_rules = rules.languages.get(f.language)
        tree = project.tree(path)
        if lang_rules is None or tree is None:
            continue
        aliases = build_alias_map(f)
        lines = project.lines(path)
        for call in nodes_of_types(tree, f.language, tuple(CALLS[f.language])):
            fn = call.child_by_field_name("constructor" if call.type == "new_expression" else "function")
            raw = _dotted(fn)
            if raw is None:
                continue
            canon = canonical_name(raw, aliases)
            positional, keywords = _arguments(call)
            for cwe in rules.risky_call_cwes:
                for spec in lang_rules.sinks.get(cwe, []):
                    if not _name_matches(spec.match, raw, canon) or not TaintAnalyzer._kw_ok(spec, keywords):
                        continue
                    idxs = range(len(positional)) if spec.args == "all" else spec.args
                    dynamic = [positional[i] for i in idxs if i < len(positional) and not is_constant(positional[i])]
                    if not dynamic:
                        continue
                    line = call.start_point[0] + 1
                    info = rules.cwes[cwe]
                    digest = hashlib.sha1(f"pattern|{cwe}|{path}|{line}".encode()).hexdigest()[:8]
                    name = canon if canon != raw else raw
                    out.setdefault((cwe, path, line), Finding(
                        finding_id=f"{cwe}-p{digest}", cwe_id=cwe, severity=Severity(info.severity),
                        confidence=round(info.confidence * rules.risky_call_confidence_factor, 2),
                        message=f"Risky call: {name}() with a non-constant argument",
                        explanation=f"{name}() is dangerous when its argument can be influenced by a user ({info.name}). "
                                    f"No data flow from an untrusted source was traced here, so this is a pattern match, "
                                    f"not a proven vulnerability.",
                        file_path=path, line_number=line, line_range=LineRange(start=line, end=call.end_point[0] + 1),
                        evidence=lines[line - 1].strip()[:200] if 0 < line <= len(lines) else None,
                        source="pattern-rule", suggested_remediation=info.remediation))
    return sorted(out.values(), key=lambda x: (x.file_path, x.line_number, x.cwe_id))
