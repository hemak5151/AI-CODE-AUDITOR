"""Expand import aliases so rules match real API names.

`from os import system as s` makes `s(...)` mean `os.system(...)`;
`const { exec } = require('child_process')` makes `exec(...)` mean `child_process.exec(...)`.
Relative imports (the repo's own code) are never expanded.
"""
from analysis_engine.parser.models import FileStructure


def build_alias_map(f: FileStructure) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for imp in f.imports:
        if imp.module.startswith("."):
            continue
        locals_for = lambda name: [l for l, i in imp.local_names.items() if i == name] or [name]  # noqa: E731
        if f.language == "python":
            if not imp.names:
                if imp.alias:
                    aliases[imp.alias] = imp.module
            else:
                for name in imp.names:
                    if name != "*":
                        for local in locals_for(name):
                            aliases[local] = f"{imp.module}.{name}"
        elif f.language == "javascript":
            if imp.alias:
                aliases[imp.alias] = imp.module
            for name in imp.names:
                if name == "*":
                    continue
                for local in locals_for(name):
                    # `import fs from 'fs'` (default import named like the module) vs `{ exec } from 'child_process'`
                    aliases[local] = imp.module if local == imp.module.split("/")[-1] else f"{imp.module}.{name}"
    return aliases


def canonical_name(name: str, aliases: dict[str, str]) -> str:
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + ("." + rest if rest else "")
    return name
