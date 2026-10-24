import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)
VULN = 'password = "secret"\nvalue = eval(user_input)\n'


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_DATA_DIR", str(tmp_path / "data"))


def run_upload(tmp_path):
    z = tmp_path / "p.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("app/vuln.py", VULN)
        zf.writestr("app/clean.py", "x = 1\n")
    with open(z, "rb") as f:
        return client.post("/api/jobs/upload", files={"file": ("p.zip", f, "application/zip")}).json()["job_id"]


def test_file_with_findings_is_served(tmp_path):
    job_id = run_upload(tmp_path)
    r = client.get(f"/api/jobs/{job_id}/file", params={"path": "app/vuln.py"})
    assert r.status_code == 200 and r.json()["content"] == VULN


def test_file_without_findings_or_unknown_is_404(tmp_path):
    job_id = run_upload(tmp_path)
    assert client.get(f"/api/jobs/{job_id}/file", params={"path": "app/clean.py"}).status_code == 404
    assert client.get(f"/api/jobs/{job_id}/file", params={"path": "../../etc/passwd"}).status_code == 404
    assert client.get("/api/jobs/nope/file", params={"path": "a.py"}).status_code == 404


def test_decisions_roundtrip(tmp_path):
    job_id = run_upload(tmp_path)
    r = client.put(f"/api/jobs/{job_id}/findings/F-1/decision", json={"decision": "accepted"})
    assert r.status_code == 200
    client.put(f"/api/jobs/{job_id}/findings/F-1/decision", json={"decision": "rejected"})
    assert client.get(f"/api/jobs/{job_id}/decisions").json() == {"F-1": "rejected"}


def test_invalid_decision_rejected(tmp_path):
    job_id = run_upload(tmp_path)
    r = client.put(f"/api/jobs/{job_id}/findings/F-1/decision", json={"decision": "maybe"})
    assert r.status_code == 422