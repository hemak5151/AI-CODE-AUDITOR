import json

from fastapi import APIRouter, HTTPException, Response

from backend.app.services import db
from backend.app.services.exports import to_pdf, to_sarif

router = APIRouter(tags=["exports"])


def _completed_job(job_id: str) -> dict:
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    if job["status"] != "completed":
        raise HTTPException(409, "Job is not completed yet")
    return job


@router.get("/jobs/{job_id}/export/sarif")
def export_sarif(job_id: str):
    job = _completed_job(job_id)
    body = json.dumps(to_sarif(job, db.get_findings(job_id)), indent=2)
    return Response(body, media_type="application/sarif+json",
                    headers={"Content-Disposition": f'attachment; filename="{job_id}.sarif"'})


@router.get("/jobs/{job_id}/export/pdf")
def export_pdf(job_id: str):
    job = _completed_job(job_id)
    return Response(to_pdf(job, db.get_findings(job_id)), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{job_id}-report.pdf"'})