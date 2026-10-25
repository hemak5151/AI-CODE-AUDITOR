from typing import Dict, Literal

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from backend.app.services import db
from backend.app.services.mock_data import MOCK_PATCHES

router = APIRouter(tags=["files and decisions"])


class Decision(BaseModel):
    decision: Literal["accepted", "rejected"]


def _require_job(job_id: str) -> None:
    if db.get_job(job_id) is None:
        raise HTTPException(404, "Job not found")


@router.get("/jobs/{job_id}/file")
def get_source_file(job_id: str, path: str):
    """Source of a file that has findings. Looked up in the database only, never on disk."""
    _require_job(job_id)
    content = db.get_file(job_id, path)
    if content is None:
        raise HTTPException(404, "File not stored for this job")
    return {"path": path, "content": content}


@router.put("/jobs/{job_id}/findings/{finding_id}/decision")
def save_decision(job_id: str, finding_id: str, body: Decision):
    _require_job(job_id)
    db.set_decision(job_id, finding_id, body.decision)
    return {"finding_id": finding_id, "decision": body.decision}


@router.get("/jobs/{job_id}/decisions")
def list_decisions(job_id: str) -> Dict[str, str]:
    _require_job(job_id)
    return db.get_decisions(job_id)


@router.get("/jobs/{job_id}/patch")
def combined_patch(job_id: str):
    """One unified diff containing every accepted patch of the job."""
    _require_job(job_id)
    accepted = [fid for fid, d in db.get_decisions(job_id).items() if d == "accepted"]
    diffs = [MOCK_PATCHES[f].unified_diff for f in accepted if f in MOCK_PATCHES and MOCK_PATCHES[f].unified_diff]
    if not diffs:
        raise HTTPException(404, "No accepted patches")
    return Response("\n".join(diffs), media_type="text/x-diff",
                    headers={"Content-Disposition": f'attachment; filename="{job_id}-accepted.patch"'})