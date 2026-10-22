from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_job_flow():
    r = client.post("/api/jobs", json={"source_type": "git", "source": "https://github.com/x/y.git"})
    assert r.status_code == 201
    job_id = r.json()["job_id"]
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "completed"
    findings = client.get(f"/api/jobs/{job_id}/findings").json()
    assert len(findings) == 3 and findings[0]["cwe_id"] == "CWE-89"


def test_patch_and_404():
    assert "unified_diff" in client.get("/api/findings/MOCK-1/patch").json()
    assert client.get("/api/jobs/nope").status_code == 404