from pathlib import Path

from analysis_engine.ingest import cleanup, from_git, from_zip
from analysis_engine.integration import analyze_job
from backend.app.services import db

# Where each analysis stage sits on the 0-100 progress bar: (from %, to %, label).
_STAGES = {
    "parse": (10, 40, "Reading"),
    "scan": (40, 55, "Scanning"),
    "taint": (55, 95, "Tracing data flow"),
}


def _reporter(job_id: str):
    """Progress callback for the analysis engine.

    Only writes to the database when the percentage changes.
    """
    last = {"pct": -1}

    def report(stage: str, done: int, total: int) -> None:
        low, high, label = _STAGES.get(stage, (10, 95, stage))
        pct = low + int((high - low) * done / max(total, 1))
        if pct != last["pct"]:
            last["pct"] = pct
            db.update_job(job_id, progress=pct, message=f"{label}: {done}/{total} files")

    return report


def run_job(job_id: str, source_type: str, location: str) -> None:
    """location = git URL, or path of an uploaded zip (deleted afterwards)."""
    root = None
    try:
        db.update_job(job_id, status="running", progress=5, message="Fetching source")
        root = from_git(location) if source_type == "git" else from_zip(location)

        db.update_job(job_id, progress=10, message="Listing files")
        # Whole-repo analysis: Python and JavaScript, data flow across files,
        # secrets and deprecated APIs.
        result = analyze_job(root, _reporter(job_id))

        db.add_findings(job_id, result.findings)
        # Every file a finding refers to, so the UI can show it.
        db.add_files(job_id, result.sources)
        db.update_job(
            job_id,
            status="completed",
            progress=100,
            files_scanned=result.files_scanned,
            message=f"Done: {len(result.findings)} finding(s)",
        )
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
