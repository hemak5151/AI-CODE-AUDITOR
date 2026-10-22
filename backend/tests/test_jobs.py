import zipfile

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)
VULN = 'password = "secret"\nvalue = eval(user_input)\n'


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_DATA_DIR", str(tmp_path / "data"))


def make_zip(path, files):
    with zipfile.ZipFile(path, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return path


def upload(path):
    with open(path, "rb") as f:
        return client.post("/api/jobs/upload", files={"file": ("project.zip", f, "application/zip")})


def test_zip_upload_finds_issues_and_ignores_node_modules(tmp_path):
    z = make_zip(tmp_path / "p.zip", {"app/vuln.py": VULN, "node_modules/x.py": "eval(y)\n"})
    r = upload(z)
    assert r.status_code == 201
    job_id = r.json()["job_id"]
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "completed" and job["progress"] == 100 and job["files_scanned"] == 1
    findings = client.get(f"/api/jobs/{job_id}/findings").json()
    assert {f["cwe_id"] for f in findings} == {"CWE-95", "CWE-798"}
    assert all(f["file_path"] == "app/vuln.py" for f in findings)


def test_zip_slip_is_rejected(tmp_path):
    z = make_zip(tmp_path / "evil.zip", {"../evil.py": "x = 1\n"})
    job_id = upload(z).json()["job_id"]
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "failed" and "Unsafe" in job["error"]


def test_non_zip_upload_rejected(tmp_path):
    r = client.post("/api/jobs/upload", files={"file": ("notes.txt", b"hi", "text/plain")})
    assert r.status_code == 422


def test_git_job(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text(VULN)
    monkeypatch.setattr("backend.app.services.jobs.from_git", lambda url: repo)
    monkeypatch.setattr("backend.app.services.jobs.cleanup", lambda p: None)
    r = client.post("/api/jobs", json={"source_type": "git", "source": "https://github.com/x/y.git"})
    assert r.status_code == 201
    job_id = r.json()["job_id"]
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "completed"
    assert len(client.get(f"/api/jobs/{job_id}/findings").json()) == 2


def test_git_url_must_be_http():
    r = client.post("/api/jobs", json={"source_type": "git", "source": "file:///etc/passwd"})
    assert r.status_code == 422


def test_events_stream_for_finished_job(tmp_path):
    job_id = upload(make_zip(tmp_path / "p.zip", {"a.py": VULN})).json()["job_id"]
    r = client.get(f"/api/jobs/{job_id}/events")
    assert r.status_code == 200
    assert '"status": "completed"' in r.text


def test_unknown_job_404():
    assert client.get("/api/jobs/nope").status_code == 404
    assert client.get("/api/jobs/nope/events").status_code == 404


def test_patch_still_mocked():
    assert "unified_diff" in client.get("/api/findings/MOCK-1/patch").json()
    assert client.get("/api/findings/NOPE/patch").status_code == 404


def test_guidelines_upload_and_list():
    r = client.post("/api/guidelines", files={"file": ("owasp.md", b"# OWASP", "text/markdown")})
    assert r.status_code == 201
    assert [g["filename"] for g in client.get("/api/guidelines").json()] == ["owasp.md"]
    bad = client.post("/api/guidelines", files={"file": ("run.exe", b"x", "application/octet-stream")})
    assert bad.status_code == 422