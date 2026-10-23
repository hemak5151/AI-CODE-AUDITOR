"""Import resolution shared by the call graph and the dependency graph.

Turns import statements into (a) which repo file each import points to and
(b) local-name bindings, so a call like `helper()` or `core.run()` can be
followed to the file that defines it. Anything that does not resolve to a file
in the repo is treated as an external package.
"""
import posixpath
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from analysis_engine.parser.models import FileStructure, ImportInfo

JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")


@dataclass
class ImportBindings:
    modules: dict[str, str] = field(default_factory=dict)  # local prefix -> repo file
    symbols: dict[str, tuple[str, str]] = field(default_factory=dict)  # local name -> (file, imported name)
    external: set[str] = field(default_factory=set)  # local names bound to external code
    targets: dict[str, set[str]] = field(default_factory=dict)  # repo file -> imported names
    external_packages: set[str] = field(default_factory=set)  # top-level external package names

    def add_target(self, path: str, names: Iterable[str]) -> None:
        self.targets.setdefault(path, set()).update(names)


def _dotted(path: str) -> str:
    parts = path[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _common_prefix_len(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


class ModuleIndex:
    """Maps module names and relative specifiers to files inside the repo."""

    def __init__(self, files: Iterable[FileStructure]):
        self.paths = {f.file_path for f in files}
        self._py: dict[str, list[str]] = defaultdict(list)
        for p in sorted(self.paths):
            if not p.endswith(".py"):
                continue
            parts = p[:-3].split("/")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            for i in range(len(parts)):  # every dotted suffix, to handle src/ layouts
                self._py[".".join(parts[i:])].append(p)

    def _py_path(self, segs: list[str]) -> Optional[str]:
        base = "/".join(segs)
        candidates = [base + ".py", base + "/__init__.py"] if segs else ["__init__.py"]
        return next((c for c in candidates if c in self.paths), None)

    def resolve_python(self, module: str, importer: str) -> Optional[str]:
        if module.startswith("."):
            dots = len(module) - len(module.lstrip("."))
            rest = module[dots:]
            parts = importer.split("/")[:-1]
            if dots - 1 > len(parts):
                return None
            base = parts[:len(parts) - (dots - 1)]
            return self._py_path(base + (rest.split(".") if rest else []))
        candidates = self._py.get(module)
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]
        importer_dir = importer.split("/")[:-1]
        return max(candidates, key=lambda c: (
            _dotted(c) == module,                                   # exact path from repo root
            _common_prefix_len(importer_dir, c.split("/")[:-1]),    # closest to the importer
            -len(c),
        ))

    def resolve_js(self, spec: str, importer: str) -> Optional[str]:
        if not spec.startswith("."):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))
        if base.startswith(".."):
            return None
        candidates = [base] + [base + e for e in JS_EXTENSIONS] + \
            [posixpath.normpath(posixpath.join(base, "index" + e)) for e in JS_EXTENSIONS]
        return next((c for c in candidates if c in self.paths), None)


def _js_package(spec: str) -> str:
    spec = spec[5:] if spec.startswith("node:") else spec
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def _locals_for(imp: ImportInfo, name: str) -> list[str]:
    aliased = [local for local, imported in imp.local_names.items() if imported == name]
    return aliased or [name]


def _python_binding(index: ModuleIndex, f: FileStructure, imp: ImportInfo, b: ImportBindings) -> None:
    module = imp.module
    if not imp.names:  # plain "import a.b.c [as x]"
        target = index.resolve_python(module, f.file_path)
        key = imp.alias or module
        if target:
            b.modules[key] = target
            b.add_target(target, [])
        else:
            b.external.update({key, key.split(".")[0]})
            b.external_packages.add(module.split(".")[0])
        return
    target = index.resolve_python(module, f.file_path)
    for name in imp.names:
        if name == "*":
            if target:
                b.add_target(target, ["*"])
            continue
        locals_ = _locals_for(imp, name)
        dotted = module + name if module.endswith(".") else module + "." + name
        sub = index.resolve_python(dotted, f.file_path)
        if sub and (target is None or target.endswith("__init__.py")):
            for local in locals_:  # "from pkg import submodule"
                b.modules[local] = sub
            b.add_target(sub, [])
        elif target:
            for local in locals_:
                b.symbols[local] = (target, name)
            b.add_target(target, [name])
        elif not module.startswith("."):
            b.external.update(locals_)
            b.external_packages.add(module.split(".")[0])


def _js_binding(index: ModuleIndex, f: FileStructure, imp: ImportInfo, b: ImportBindings) -> None:
    target = index.resolve_js(imp.module, f.file_path)
    locals_ = [l for n in imp.names if n != "*" for l in _locals_for(imp, n)]
    if imp.alias:
        locals_.append(imp.alias)
    if target is None:
        if not imp.module.startswith("."):
            b.external.update(locals_)
            b.external_packages.add(_js_package(imp.module))
        return
    b.add_target(target, imp.names)
    if imp.alias:
        b.modules[imp.alias] = target  # namespace import or require alias
    for name in imp.names:
        if name != "*":
            for local in _locals_for(imp, name):
                b.symbols[local] = (target, name)


def build_bindings(index: ModuleIndex, f: FileStructure) -> ImportBindings:
    b = ImportBindings()
    for imp in f.imports:
        if f.language == "python":
            _python_binding(index, f, imp, b)
        elif f.language == "javascript":
            _js_binding(index, f, imp, b)
    return b
