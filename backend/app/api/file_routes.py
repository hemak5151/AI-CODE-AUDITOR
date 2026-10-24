from typing import Dict, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.services import db

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