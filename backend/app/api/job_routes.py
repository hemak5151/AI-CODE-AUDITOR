import json
import tempfile
import time
from pathlib import Path
from typing import List, Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from backend.app.services import db
from backend.app.services.jobs import run_job
from backend.app.services.mock_data import MOCK_PATCHES
from shared.schemas.finding import Finding
from shared.schemas.interfaces import Patch

router = APIRouter(tags=["jobs"])
MAX_ZIP_BYTES = 100 * 1024 * 1024


class JobCreate(BaseModel):
    source_type: Literal["git"] = "git"
    source: str  # https git URL

    @field_validator("source")
    @classmethod
    def only_http_urls(cls, v: str) -> str:
        if not v.startswith(("https://", "http://")):
            raise ValueError("source must be an http(s) git URL")
        return v


class Job(BaseModel):
    job_id: str
    source_type: str
    source: str
    status: Literal["queued", "running", "completed", "failed"]
    progress: int
    message: str = ""
    error: Optional[str] = None
    files_scanned: int = 0


def _job_or_404(job_id: str) -> dict:
    job = db.get_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found")
    return job


@router.post("/jobs", response_model=Job, status_code=201)
def create_git_job(body: JobCreate, background_tasks: BackgroundTasks):
    job_id = uuid4().hex[:8]
    db.create_job(job_id, "git", body.source)
    background_tasks.add_task(run_job, job_id, "git", body.source)
    return _job_or_404(job_id)


@router.post("/jobs/upload", response_model=Job, status_code=201)
def upload_zip(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    name = Path(file.filename or "").name
    if not name.lower().endswith(".zip"):
        raise HTTPException(422, "Upload a .zip file")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    size = 0
    try:
        with tmp:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_ZIP_BYTES:
                    raise HTTPException(413, "Zip is larger than 100 MB")
                tmp.write(chunk)
    except HTTPException:
        Path(tmp.name).unlink(missing_ok=True)
        raise
    job_id = uuid4().hex[:8]
    db.create_job(job_id, "zip", name)
    background_tasks.add_task(run_job, job_id, "zip", tmp.name)
    return _job_or_404(job_id)


@router.get("/jobs/{job_id}", response_model=Job)
def get_job(job_id: str):
    return _job_or_404(job_id)


@router.get("/jobs/{job_id}/findings", response_model=List[Finding])
def get_findings(job_id: str):
    _job_or_404(job_id)
    return db.get_findings(job_id)


@router.get("/jobs/{job_id}/events")
def job_events(job_id: str):
    """Server-Sent Events: one message per progress change, closes when the job ends."""
    _job_or_404(job_id)

    def stream():
        last = None
        while True:
            job = db.get_job(job_id)
            if job is None:
                return
            payload = json.dumps({k: job[k] for k in ("job_id", "status", "progress", "message", "error")})
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
            if job["status"] in ("completed", "failed"):
                return
            time.sleep(0.5)

    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/findings/{finding_id}/patch", response_model=Patch)
def get_patch(finding_id: str):
    # Still mock data until Member 3's patch generator is connected.
    if finding_id not in MOCK_PATCHES:
        raise HTTPException(404, "No patch for this finding")
    return MOCK_PATCHES[finding_id]