from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.app.services.db import data_dir

router = APIRouter(tags=["guidelines"])
ALLOWED = {".pdf", ".md", ".markdown", ".txt"}
MAX_BYTES = 20 * 1024 * 1024


def _folder() -> Path:
    d = data_dir() / "guidelines"
    d.mkdir(parents=True, exist_ok=True)
    return d


@router.post("/guidelines", status_code=201)
def upload_guideline(file: UploadFile = File(...)):
    name = Path(file.filename or "").name  # strips any folder parts
    if Path(name).suffix.lower() not in ALLOWED:
        raise HTTPException(422, "Allowed types: .pdf, .md, .markdown, .txt")
    content = file.file.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise HTTPException(413, "File is larger than 20 MB")
    (_folder() / name).write_bytes(content)
    return {"filename": name, "size_bytes": len(content)}


@router.get("/guidelines")
def list_guidelines():
    return [{"filename": p.name, "size_bytes": p.stat().st_size} for p in sorted(_folder().iterdir()) if p.is_file()]