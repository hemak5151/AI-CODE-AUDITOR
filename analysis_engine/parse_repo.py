"""Parse a whole repo end to end into normalized structure JSON.

Usage (from the project root):
    python -m analysis_engine.parse_repo <folder | repo.zip | git-url> [--json out.json]
"""
import argparse
import json
from pathlib import Path

from analysis_engine.ingest import from_git, from_zip, iter_source_files
from analysis_engine.parser.structure import extract_file


def parse_repo(root: Path) -> dict:
    root = Path(root)
    files = [extract_file(path, root) for path, _language in iter_source_files(root)]
    by_language: dict[str, int] = {}
    for f in files:
        by_language[f.language] = by_language.get(f.language, 0) + 1
    summary = {
        "files": len(files),
        "with_errors": sum(1 for f in files if f.parse_error),
        "functions": sum(len(f.functions) for f in files),
        "classes": sum(len(f.classes) for f in files),
        "imports": sum(len(f.imports) for f in files),
        "by_language": by_language,
    }
    return {"summary": summary, "files": [f.model_dump() for f in files]}


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse a repo with Tree-Sitter")
    ap.add_argument("target", help="folder, .zip file, or git URL")
    ap.add_argument("--json", dest="json_out", help="write full results to this file")
    args = ap.parse_args()

    if args.target.endswith(".zip"):
        root = from_zip(args.target)
    elif args.target.startswith(("http://", "https://", "git@")):
        root = from_git(args.target)
    else:
        root = Path(args.target)

    result = parse_repo(root)
    for f in result["files"][:25]:
        flag = f"  ERROR: {f['parse_error']}" if f["parse_error"] else ""
        print(f"{f['file_path']}: {len(f['functions'])} functions, {len(f['classes'])} classes{flag}")
    if len(result["files"]) > 25:
        print(f"... and {len(result['files']) - 25} more files")
    print("\nSUMMARY")
    print(json.dumps(result["summary"], indent=2))
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nFull results written to {args.json_out}")


if __name__ == "__main__":
    main()
