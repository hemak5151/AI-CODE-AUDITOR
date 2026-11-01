"""Taint analysis: follow untrusted values from sources to dangerous sinks.

How it works
  1. Every function (and each file's top-level code) is a unit. Inside a unit we walk the
     code in order, keeping a map  variable -> where its taint came from.
  2. Sources (request.args, input(), req.query, ...) create taint. Assignments, string
     building, f-strings and ordinary calls pass it on. Sanitizers (int(), shlex.quote(),
     basename(), ...) clear it for the CWEs they protect against.
  3. A call to a sink (cursor.execute, os.system, open, pickle.loads, ...) with a tainted
     argument is a hit.
  4. Parameters start as symbolic taint, so each function gets a summary
     ("parameter 0 reaches cursor.execute"). Summaries are applied at call sites, which gives
     cross-function and cross-file flows. Summaries are recomputed until they stop changing.
  5. A function nobody calls is treated as an entry point: its parameters count as
     outside input, with lower confidence.

Limits (by design): no type inference, branches are merged, loops run once, aliasing through
containers is approximate. Rules live in security/rule_data/taint.yaml.
"""
import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import Optional

from analysis_engine.parser.models import FunctionInfo
from analysis_engine.project import FUNC_TYPES, Project, is_test_or_example_path
from analysis_engine.security.aliases import build_alias_map, canonical_name
from analysis_engine.security.rule_loader import SinkSpec, TaintRules, load_taint_rules
from shared.schemas import Finding, LineRange, Severity

DOTTED = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")
IDENT = re.compile(r"^[A-Za-z_$][\w$]*$")
SELF_NAMES = {"self", "cls", "this"}
MAX_STEPS = 12
MAX_FLOWS_PER_PARAM = 20
MAX_ROUNDS = 5

ASSIGN = {"python": {"assignment", "augmented_assignment"},
          "javascript": {"variable_declarator", "assignment_expression", "augmented_assignment_expression"}}
FOR = {"python": {"for_statement"}, "javascript": {"for_in_statement"}}
CALLS = {"python": {"call"}, "javascript": {"call_expression", "new_expression"}}
RETURNS = {"return_statement"}
FUNC_LITERALS = {"lambda", "arrow_function", "function_expression", "function", "generator_function"}
TUPLE_LIKE = {"pattern_list", "tuple_pattern", "list_pattern", "tuple", "list", "array_pattern",
              "object_pattern", "pair_pattern", "rest_pattern", "list_splat_pattern", "parenthesized_expression",
              "as_pattern_target"}
NAME_NODES = {"identifier", "shorthand_property_identifier_pattern"}


# ------------------------------------------------------------------ data
@dataclass(frozen=True)
class Step:
    file: str
    line: int
    kind: str  # source | propagation | call | sanitizer | sink
    text: str

    def fmt(self) -> str:
        return f"{self.file}:{self.line} {self.kind}: {self.text}"


@dataclass(frozen=True)
class Taint:
    path: tuple
    sanitized: frozenset = frozenset()

    def clears(self, cwe: str) -> bool:
        return "*" in self.sanitized or cwe in self.sanitized


TaintSet = dict  # origin key -> Taint.   origin = ("source", description, file, line) | ("param", index)


def _cap(path: tuple) -> tuple:
    return path if len(path) <= MAX_STEPS else path[:3] + path[-(MAX_STEPS - 3):]


def _extend(ts: TaintSet, step: Step, clears: frozenset = frozenset()) -> TaintSet:
    return {k: Taint(_cap(t.path + (step,)), t.sanitized | clears) for k, t in ts.items()}


def _merge(*sets) -> TaintSet:
    out: TaintSet = {}
    for s in sets:
        for k, t in s.items():
            cur = out.get(k)
            if cur is None:
                out[k] = t
            elif cur.sanitized - t.sanitized:  # sanitized only if sanitized on every path
                out[k] = Taint(cur.path, cur.sanitized & t.sanitized)
    return out


@dataclass(frozen=True)
class SinkFlow:
    """A parameter reaching a sink, as recorded in a function summary."""
    cwe: str
    sink_name: str
    file: str
    line: int
    unit: tuple
    steps: tuple


@dataclass
class Summary:
    param_sinks: dict = field(default_factory=dict)       # param index -> [SinkFlow]
    param_to_return: set = field(default_factory=set)
    returns_source: dict = field(default_factory=dict)    # static source taint that reaches `return`

    def signature(self):
        return (tuple(sorted((i, tuple(sorted((f.cwe, f.file, f.line, len(f.steps)) for f in fl)))
                             for i, fl in self.param_sinks.items())),
                tuple(sorted(self.param_to_return)), tuple(sorted(self.returns_source)))


@dataclass
class SinkHit:
    cwe: str
    name: str
    line: int
    taints: TaintSet


@dataclass
class CallHit:
    callee: tuple
    line: int
    text: str
    param_taints: dict  # callee param index -> TaintSet


@dataclass
class UnitResult:
    sink_hits: list = field(default_factory=list)
    call_hits: list = field(default_factory=list)
    returns: dict = field(default_factory=dict)


@dataclass
class Unit:
    key: tuple          # (file, qualified_name); qualified_name "" means the file's top-level code
    file: str
    language: str
    node: object
    info: Optional[FunctionInfo]

    @property
    def params(self) -> list:
        return self.info.params if self.info else []


@dataclass
class Flow:
    cwe: str
    sink_name: str
    sink_file: str
    sink_line: int
    sink_unit: tuple
    source_desc: str
    source_file: str
    source_line: int
    steps: tuple
    interprocedural: bool
    entry_param: bool


# ------------------------------------------------------------------ helpers
def _dotted(node) -> Optional[str]:
    if node is not None and node.type in ("identifier", "attribute", "member_expression", "this", "property_identifier"):
        text = node.text.decode("utf-8", errors="replace")
        return text if DOTTED.match(text) else None
    return None


def _snippet(node, limit: int = 80) -> str:
    text = " ".join(node.text.decode("utf-8", errors="replace").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _name_matches(patterns: list, raw: Optional[str], canon: Optional[str]) -> Optional[str]:
    for p in patterns:
        for name in (raw, canon):
            if not name:
                continue
            if p.startswith("."):
                if name.endswith(p):
                    return p
            elif name == p:
                return p
    return None


def _source_matches(patterns: list, raw: Optional[str], canon: Optional[str]) -> Optional[str]:
    for p in patterns:
        for name in (raw, canon):
            if name and (name == p or name.startswith(p + ".")):
                return p
    return None


# ------------------------------------------------------------------ analyzer
class TaintAnalyzer:
    def __init__(self, project: Project, rules: Optional[TaintRules] = None, entry_point_params: bool = True):
        self.project = project
        self.rules = rules or load_taint_rules()
        self.entry_point_params = entry_point_params
        self.aliases = {p: build_alias_map(f) for p, f in project.file_map.items()}
        self.summaries: dict = {}
        self.units: dict = {}
        self._known: dict = {}
        self._resolved: dict = {}
        for path, f in project.file_map.items():
            if f.language not in self.rules.languages:
                continue
            tree = project.tree(path)
            if tree is None:
                continue
            self.units[(path, "")] = Unit((path, ""), path, f.language, tree.root_node, None)
            spans = set()
            for fn in f.functions:
                node = project.function_node(path, fn)
                if node is not None:
                    spans.add((fn.start_line, fn.end_line))
                    self.units.setdefault((path, fn.qualified_name),
                                          Unit((path, fn.qualified_name), path, f.language, node, fn))
            self._known[path] = spans

    # -- public --------------------------------------------------------
    def run(self) -> list:
        results: dict = {}
        for _ in range(MAX_ROUNDS):
            results = {k: self._analyze(u) for k, u in self.units.items()}
            new = {k: self._summarize(k, r) for k, r in results.items()}
            stable = all(new[k].signature() == self.summaries.get(k, Summary()).signature() for k in new)
            self.summaries = new
            if stable:
                break
        return self._collect(results)

    # -- one unit ------------------------------------------------------
    def _analyze(self, unit: Unit) -> UnitResult:
        res = UnitResult()
        env: dict = {}
        for i, name in enumerate(unit.params):
            if IDENT.match(name):
                env[name] = {("param", i): Taint(())}
        known = self._known.get(unit.file, set())
        kinds = FUNC_TYPES.get(unit.language, set())
        stack = [unit.node]
        while stack:
            node = stack.pop()
            if node is not unit.node and node.type in kinds and \
                    (node.start_point[0] + 1, node.end_point[0] + 1) in known:
                continue  # a named function: analysed as its own unit
            try:
                self._visit(node, unit, env, res)
            except RecursionError:
                pass
            stack.extend(reversed(node.children))
        if unit.node.type == "arrow_function":  # expression-bodied arrow: the body is the return value
            body = unit.node.child_by_field_name("body")
            if body is not None and body.type != "statement_block":
                res.returns = _merge(res.returns, self._eval(body, unit, env))
        return res

    def _visit(self, node, unit: Unit, env: dict, res: UnitResult) -> None:
        lang, t = unit.language, node.type
        if t in ASSIGN[lang]:
            left = node.child_by_field_name("name" if t == "variable_declarator" else "left")
            right = node.child_by_field_name("value" if t == "variable_declarator" else "right")
            if left is not None and right is not None:
                ts = self._eval(right, unit, env)
                if t.startswith("augmented"):
                    ts = _merge(ts, self._eval(left, unit, env))
                self._assign(left, ts, unit, env)
        elif t == "as_pattern" and lang == "python":  # with open(p) as f:
            alias = node.child_by_field_name("alias")
            if node.named_children and alias is not None:
                self._assign(alias, self._eval(node.named_children[0], unit, env), unit, env)
        elif t in FOR[lang]:
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None:
                self._assign(left, self._eval(right, unit, env), unit, env)
        elif t in CALLS[lang]:
            self._visit_call(node, unit, env, res)
        elif t in RETURNS:
            for child in node.named_children:
                res.returns = _merge(res.returns, self._eval(child, unit, env))

    # -- assignments ---------------------------------------------------
    def _assign(self, left, ts: TaintSet, unit: Unit, env: dict) -> None:
        names = self._target_names(left)
        step = Step(unit.file, left.start_point[0] + 1, "propagation", f"{_snippet(left, 30)} = ...")
        for name in names:
            if ts:
                env[name] = _extend(ts, step)
            else:
                env.pop(name, None)
        if left.type in ("subscript", "subscript_expression") and ts:  # d["k"] = tainted: taint the container
            base = _dotted(left.child_by_field_name("value") or left.child_by_field_name("object"))
            if base:
                env[base] = _merge(env.get(base, {}), _extend(ts, step))

    def _target_names(self, node) -> list:
        if node.type in NAME_NODES:
            return [node.text.decode()]
        if node.type in ("attribute", "member_expression"):
            d = _dotted(node)
            return [d] if d else []
        if node.type in TUPLE_LIKE:
            out = []
            for c in node.named_children:
                if c.type == "pair_pattern":
                    value = c.child_by_field_name("value")
                    out.extend(self._target_names(value) if value is not None else [])
                else:
                    out.extend(self._target_names(c))
            return out
        return []

    # -- expressions ---------------------------------------------------
    def _eval(self, node, unit: Unit, env: dict) -> TaintSet:
        t = node.type
        if t in FUNC_LITERALS:
            return {}
        if t in ("identifier", "this"):
            return env.get(node.text.decode(), {})
        if t in ("attribute", "member_expression"):
            text = _dotted(node)
            if text:
                if text in env:
                    return env[text]
                src = self._source(text, unit, node)
                if src:
                    return src
            obj = node.child_by_field_name("object")
            return self._eval(obj, unit, env) if obj is not None else {}
        if t in CALLS[unit.language]:
            return self._eval_call(node, unit, env)
        return _merge(*[self._eval(c, unit, env) for c in node.named_children if c.type != "comment"])

    def _source(self, raw: Optional[str], unit: Unit, node) -> TaintSet:
        rules = self.rules.languages[unit.language]
        canon = canonical_name(raw, self.aliases[unit.file]) if raw else None
        hit = _source_matches(rules.sources, raw, canon)
        if not hit:
            return {}
        line = node.start_point[0] + 1
        return {("source", hit, unit.file, line): Taint((Step(unit.file, line, "source", _snippet(node)),))}

    def _call_parts(self, node):
        if node.type == "new_expression":
            fn = node.child_by_field_name("constructor")
        else:
            fn = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
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
        return fn, positional, keywords

    def _resolve(self, unit: Unit, name: str):
        key = (unit.file, unit.key[1], name)
        if key not in self._resolved:
            res = self.project.resolver.resolve_call(unit.file, unit.key[1], name)
            target = None
            if res and res[0] == "function":
                target = (res[1], res[2])
            elif res and res[0] == "class":
                ctor = self.project.resolver.constructor(res[1], res[2])
                target = (ctor[1], ctor[2]) if ctor else None
            self._resolved[key] = (target, bool(res and res[0] == "class"))
        return self._resolved[key]

    def _offset(self, callee_key: tuple, name: str, is_ctor: bool, unit: Unit) -> int:
        callee = self.units.get(callee_key)
        if not callee or not callee.info or callee.info.kind != "method":
            return 0
        if not callee.info.params or callee.info.params[0] not in ("self", "cls"):
            return 0
        if is_ctor:
            return 1
        head = name.split(".")[0]
        if "." not in name:
            return 0
        ent = self.project.resolver.entity(unit.file, head)
        return 0 if ent and ent[0] == "class" else 1

    def _eval_call(self, node, unit: Unit, env: dict) -> TaintSet:
        fn, positional, keywords = self._call_parts(node)
        raw = _dotted(fn)
        canon = canonical_name(raw, self.aliases[unit.file]) if raw else None
        rules = self.rules.languages[unit.language]
        src = _source_matches(rules.sources, raw, canon)
        if src:
            line = node.start_point[0] + 1
            return {("source", src, unit.file, line): Taint((Step(unit.file, line, "source", _snippet(node)),))}
        arg_sets = [self._eval(a, unit, env) for a in positional] + [self._eval(v, unit, env) for v in keywords.values()]
        for san in rules.sanitizers:
            if _name_matches(san.match, raw, canon):
                clears = frozenset({"*"}) if san.clears == "all" else frozenset(san.clears)
                step = Step(unit.file, node.start_point[0] + 1, "sanitizer", _snippet(node, 60))
                return _extend(_merge(*arg_sets), step, clears)
        if raw:
            target, is_ctor = self._resolve(unit, raw)
            summary = self.summaries.get(target) if target else None
            if target and summary is not None:
                out: TaintSet = dict(summary.returns_source)
                offset = self._offset(target, raw, is_ctor, unit)
                for idx in summary.param_to_return:
                    j = idx - offset
                    if 0 <= j < len(positional):
                        out = _merge(out, arg_sets[j])
                    name = self.units[target].params[idx] if idx < len(self.units[target].params) else None
                    if name in keywords:
                        out = _merge(out, self._eval(keywords[name], unit, env))
                return out
        receiver = {}
        if fn is not None and fn.type in ("attribute", "member_expression"):
            obj = fn.child_by_field_name("object")
            receiver = self._eval(obj, unit, env) if obj is not None else {}
        return _merge(receiver, *arg_sets)

    # -- calls: sink checks and call-site recording --------------------
    def _visit_call(self, node, unit: Unit, env: dict, res: UnitResult) -> None:
        fn, positional, keywords = self._call_parts(node)
        raw = _dotted(fn)
        if raw is None:
            return
        canon = canonical_name(raw, self.aliases[unit.file])
        rules = self.rules.languages[unit.language]
        arg_sets = [self._eval(a, unit, env) for a in positional]
        kw_sets = {k: self._eval(v, unit, env) for k, v in keywords.items()}
        line = node.start_point[0] + 1
        for cwe, specs in rules.sinks.items():
            for spec in specs:
                if not _name_matches(spec.match, raw, canon) or not self._kw_ok(spec, keywords):
                    continue
                idxs = range(len(positional)) if spec.args == "all" else spec.args
                taints = _merge(*[arg_sets[i] for i in idxs if i < len(positional)])
                if taints:
                    res.sink_hits.append(SinkHit(cwe, canon if canon != raw else raw, line, taints))
        target, is_ctor = self._resolve(unit, raw)
        if target and target in self.units:
            offset = self._offset(target, raw, is_ctor, unit)
            params = self.units[target].params
            by_param: dict = {}
            for j, ts in enumerate(arg_sets):
                if ts:
                    by_param[j + offset] = ts
            for name, ts in kw_sets.items():
                if ts and name in params:
                    by_param[params.index(name)] = _merge(by_param.get(params.index(name), {}), ts)
            if by_param:
                res.call_hits.append(CallHit(target, line, f"{raw}(...)", by_param))

    @staticmethod
    def _kw_ok(spec: SinkSpec, keywords: dict) -> bool:
        for key, wanted in spec.requires_kw.items():
            node = keywords.get(key)
            if node is None or node.text.decode().strip().lower() != wanted.lower():
                return False
        for key, safe_values in spec.unless_kw.items():
            node = keywords.get(key)
            if node is not None and node.text.decode().strip().split(".")[-1] in safe_values:
                return False
        return True

    # -- summaries and flows -------------------------------------------
    def _summarize(self, key: tuple, res: UnitResult) -> Summary:
        s = Summary()
        unit = self.units[key]

        def add(idx: int, flow: SinkFlow) -> None:
            bucket = s.param_sinks.setdefault(idx, [])
            ident = (flow.cwe, flow.file, flow.line)
            if len(bucket) < MAX_FLOWS_PER_PARAM and all((f.cwe, f.file, f.line) != ident for f in bucket):
                bucket.append(flow)

        for hit in res.sink_hits:
            for origin, t in hit.taints.items():
                if origin[0] == "param" and not t.clears(hit.cwe):
                    step = Step(unit.file, hit.line, "sink", f"{hit.name}(...)")
                    add(origin[1], SinkFlow(hit.cwe, hit.name, unit.file, hit.line, key, _cap(t.path + (step,))))
        for ch in res.call_hits:
            callee = self.summaries.get(ch.callee)
            if callee is None:
                continue
            call_step = Step(unit.file, ch.line, "call", ch.text)
            for idx, taints in ch.param_taints.items():
                for sf in callee.param_sinks.get(idx, []):
                    for origin, t in taints.items():
                        if origin[0] == "param" and not t.clears(sf.cwe):
                            add(origin[1], SinkFlow(sf.cwe, sf.sink_name, sf.file, sf.line, sf.unit,
                                                    _cap(t.path + (call_step,) + sf.steps)))
        for origin, t in res.returns.items():
            if origin[0] == "param":
                s.param_to_return.add(origin[1])
            else:
                s.returns_source[origin] = t
        return s

    def _collect(self, results: dict) -> list:
        flows: dict = {}

        def keep(flow: Flow) -> None:
            ident = (flow.cwe, flow.sink_file, flow.sink_line, flow.source_desc, flow.source_file, flow.source_line)
            if ident not in flows or len(flow.steps) < len(flows[ident].steps):
                flows[ident] = flow

        for key, res in results.items():
            unit = self.units[key]
            for hit in res.sink_hits:
                for origin, t in hit.taints.items():
                    if origin[0] == "source" and not t.clears(hit.cwe):
                        step = Step(unit.file, hit.line, "sink", f"{hit.name}(...)")
                        keep(Flow(hit.cwe, hit.name, unit.file, hit.line, key, origin[1], origin[2], origin[3],
                                  _cap(t.path + (step,)), False, False))
            for ch in res.call_hits:
                callee = self.summaries.get(ch.callee)
                if callee is None:
                    continue
                call_step = Step(unit.file, ch.line, "call", ch.text)
                for idx, taints in ch.param_taints.items():
                    for sf in callee.param_sinks.get(idx, []):
                        for origin, t in taints.items():
                            if origin[0] == "source" and not t.clears(sf.cwe):
                                keep(Flow(sf.cwe, sf.sink_name, sf.file, sf.line, sf.unit, origin[1], origin[2],
                                          origin[3], _cap(t.path + (call_step,) + sf.steps), True, False))
            if self.entry_point_params and unit.info is not None and not is_test_or_example_path(unit.file) and \
                    self.project.is_entry_point(unit.file, unit.info.qualified_name):
                for idx, sfs in self.summaries[key].param_sinks.items():
                    name = unit.params[idx] if idx < len(unit.params) else ""
                    if not IDENT.match(name) or name in SELF_NAMES:
                        continue
                    start = Step(unit.file, unit.info.start_line, "source", f"parameter '{name}' of {unit.info.qualified_name}()")
                    for sf in sfs:
                        keep(Flow(sf.cwe, sf.sink_name, sf.file, sf.line, sf.unit,
                                  f"parameter '{name}' of {unit.info.qualified_name}()", unit.file, unit.info.start_line,
                                  _cap((start,) + sf.steps), any(s.kind == "call" for s in sf.steps), True))
        # Many uncalled functions can reach the same sink line. Report that sink once (the
        # shortest path) and say how many other entry points lead to it.
        real = [f for f in flows.values() if not f.entry_param]
        grouped: dict = {}
        for f in flows.values():
            if f.entry_param:
                grouped.setdefault((f.cwe, f.sink_file, f.sink_line), []).append(f)
        merged = []
        for group in grouped.values():
            best = min(group, key=lambda f: (len(f.steps), f.source_desc))
            extra = len(group) - 1
            if extra:
                best = replace(best, source_desc=f"{best.source_desc} (and {extra} other uncalled "
                                                 f"function{'s' if extra > 1 else ''})")
            merged.append(best)
        return sorted(real + merged, key=lambda f: (f.sink_file, f.sink_line, f.cwe, f.source_desc))


# ------------------------------------------------------------------ findings
def flow_to_finding(flow: Flow, rules: TaintRules, project: Project) -> Finding:
    info = rules.cwes[flow.cwe]
    confidence = info.confidence * (0.9 if flow.interprocedural else 1.0) * (0.65 if flow.entry_param else 1.0)
    lines = project.lines(flow.sink_file)
    code = lines[flow.sink_line - 1].strip() if 0 < flow.sink_line <= len(lines) else ""
    evidence = "\n".join(
        ("" if i == 0 else "-> ") + f"{s.text}  [{s.file}:{s.line}]" for i, s in enumerate(flow.steps))
    where = " (across functions)" if flow.interprocedural else ""
    digest = hashlib.sha1(f"{flow.cwe}|{flow.sink_file}|{flow.sink_line}|{flow.source_desc}|{flow.source_line}".encode()).hexdigest()[:8]
    return Finding(
        finding_id=f"{flow.cwe}-{digest}", cwe_id=flow.cwe, severity=Severity(info.severity),
        confidence=round(min(confidence, 1.0), 2),
        message=f"{info.name} via {flow.sink_name}()",
        explanation=f"{info.name}: untrusted data from {flow.source_desc} reaches {flow.sink_name}() "
                    f"without sanitization{where}. Sink: {code}",
        file_path=flow.sink_file, line_number=flow.sink_line,
        line_range=LineRange(start=flow.sink_line, end=flow.sink_line),
        evidence=evidence, source="taint-engine-entry" if flow.entry_param else "taint-engine",
        suggested_remediation=info.remediation)


def find_taint_flows(project: Project, rules: Optional[TaintRules] = None, entry_point_params: bool = True) -> list:
    return TaintAnalyzer(project, rules, entry_point_params).run()
