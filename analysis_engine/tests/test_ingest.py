import zipfile

import pytest

from analysis_engine.ingest import from_zip, iter_source_files
from analysis_engine.parse_repo import parse_repo


def _make_repo(root):
    (root / "app.py").write_text("def f():\n    return 1\n")
    (root / "web.js").write_text("function g() { return 2 }\n")
    (root / "notes.txt").write_text("ignore me")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("function x(){}")
    (root / "venv").mkdir()
    (root / "venv" / "lib.py").write_text("def y(): pass")


def test_ignored_folders_and_unsupported_files_skipped(tmp_path):
    _make_repo(tmp_path)
    names = sorted(p.name for p, _ in iter_source_files(tmp_path))
    assert names == ["app.py", "web.js"]


def test_zip_ingestion(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _make_repo(src)
    zpath = tmp_path / "repo.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        for p in src.rglob("*"):
            zf.write(p, p.relative_to(src))
    out = from_zip(str(zpath), str(tmp_path / "out"))
    assert (out / "app.py").exists()


def test_zip_slip_rejected(tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil.py", "x=1")
    with pytest.raises(ValueError):
        from_zip(str(zpath), str(tmp_path / "out"))


def test_parse_repo_summary(tmp_path):
    _make_repo(tmp_path)
    (tmp_path / "bad.py").write_text("def broken(:\n")
    result = parse_repo(tmp_path)
    assert result["summary"]["files"] == 3
    assert result["summary"]["with_errors"] == 1
    assert result["summary"]["by_language"] == {"python": 2, "javascript": 1}
