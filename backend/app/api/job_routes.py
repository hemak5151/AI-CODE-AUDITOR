from typing import Dict, List, Literal
from uuid import uuid4
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from shared.schemas.finding import Finding
from shared.schemas.interfaces import Patch
from backend.app.services.mock_data import MOCK_FINDINGS, MOCK_PATCHES

router = APIRouter(tags=["jobs (mock)"])


class JobCreate(BaseModel):
    source_type: Literal["zip", "git"]
    source: str  # zip file name or git URL


class Job(BaseModel):
    job_id: str
    source_type: str
    source: str
    status: Literal["queued", "running", "completed", "failed"]
    progress: int


JOBS: Dict[str, Job] = {}


@router.post("/jobs", response_model=Job, status_code=201)
def create_job(body: JobCreate):
    job = Job(job_id=uuid4().hex[:8], source_type=body.source_type,
              source=body.source, status="completed", progress=100)
    JOBS[job.job_id] = job
    return job


@router.get("/jobs/{job_id}", response_model=Job)
def get_job(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    return JOBS[job_id]


@router.get("/jobs/{job_id}/findings", response_model=List[Finding])
def get_findings(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    return MOCK_FINDINGS


@router.get("/findings/{finding_id}/patch", response_model=Patch)
def get_patch(finding_id: str):
    if finding_id not in MOCK_PATCHES:
        raise HTTPException(404, "No patch for this finding")
    return MOCK_PATCHES[finding_id]