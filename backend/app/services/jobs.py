from pathlib import Path
from typing import Dict, List

from analysis_engine import analyze_python
from analysis_engine.ingest import cleanup, from_git, from_zip, iter_source_files
from backend.app.services import db


def run_job(job_id: str, source_type: str, location: str) -> None:
    """location = git URL, or path of an uploaded zip (deleted afterwards)."""
    root = None
    try:
        db.update_job(job_id, status="running", progress=5, message="Fetching source")
        root = from_git(location) if source_type == "git" else from_zip(location)

        db.update_job(job_id, progress=10, message="Listing files")
        files = list(iter_source_files(root))
        total = len(files) or 1

        collected: List[dict] = []
        sources: Dict[str, str] = {}
        counter = 0
        for i, (path, language) in enumerate(files, 1):
            if language == "python":
                rel = path.relative_to(root).as_posix()
                text = path.read_text(encoding="utf-8", errors="replace")
                found = analyze_python(text).findings
                if found:
                    sources[rel] = text  # keep the source so the UI can show the whole file
                for f in found:
                    counter += 1
                    fixed = f.model_copy(update={"file_path": rel, "finding_id": f"{f.finding_id}-{counter}"})
                    collected.append(fixed.model_dump(mode="json"))
            db.update_job(job_id, progress=10 + int(85 * i / total), message=f"Scanned {i}/{len(files)} files")

        db.add_findings(job_id, collected)
        db.add_files(job_id, sources)
        db.update_job(job_id, status="completed", progress=100, files_scanned=len(files),
                      message=f"Done: {len(collected)} finding(s)")
    except Exception as exc:  # report any failure on the job instead of crashing the worker
        db.update_job(job_id, status="failed", message="Failed", error=str(exc)[:500])
    finally:
        if source_type == "zip":
            Path(location).unlink(missing_ok=True)
        if root is not None:
            try:
                cleanup(root)
            except Exception:
                pass