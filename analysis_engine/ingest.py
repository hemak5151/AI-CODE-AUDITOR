"""Repo ingestion: local folder, zip upload, or git clone, with file filtering."""
import os
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Iterator, Optional

from analysis_engine.parser.treesitter_parser import EXT_TO_LANGUAGE

IGNORE_DIRS = {
    "node_modules", "venv", ".venv", "env", "build", "dist", "__pycache__",
    ".git", ".idea", ".vscode", ".mypy_cache", ".pytest_cache", "site-packages",
    ".next", "coverage",
}
MAX_FILE_BYTES = 1_000_000  # skip huge or minified files


def from_zip(zip_path: str, dest: Optional[str] = None) -> Path:
    dest_path = Path(dest or tempfile.mkdtemp(prefix="repo_")).resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():  # guard against zip-slip
            target = (dest_path / member).resolve()
            if dest_path != target and dest_path not in target.parents:
                raise ValueError(f"Unsafe path in zip: {member}")
        zf.extractall(dest_path)
    return dest_path


def from_git(url: str, dest: Optional[str] = None) -> Path:
    dest_path = Path(dest or tempfile.mkdtemp(prefix="repo_"))
    subprocess.run(["git", "clone", "--depth", "1", url, str(dest_path)], check=True)
    return dest_path


def iter_source_files(root: Path) -> Iterator[tuple[Path, str]]:
    """Yield (path, language) for supported files, skipping ignored folders."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]  # prune early
        for name in filenames:
            path = Path(dirpath) / name
            language = EXT_TO_LANGUAGE.get(path.suffix.lower())
            if language and path.stat().st_size <= MAX_FILE_BYTES:
                yield path, language


def cleanup(path: Path) -> None:
    def _force(func, p, _exc):  # Windows: .git files are read-only
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=_force)
