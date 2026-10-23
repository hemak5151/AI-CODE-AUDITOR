import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.services import db
from shared.schemas.finding import Finding, Severity

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_data(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_DATA_DIR", str(tmp_path / "data"))


def seed(job_id="job1", status="completed"):
    db.create_job(job_id, "zip", "p.zip")
    db.update_job(job_id, status=status, progress=100, files_scanned=1)
    f = Finding(finding_id="F-1", cwe_id="CWE-798", severity=Severity.MEDIUM, confidence=0.9,
                message="Hardcoded secret", explanation="A credential is in the source.",
                file_path="a.py", line_number=3, evidence='password = "x"', source="test")
    db.add_findings(job_id, [f.model_dump(mode="json")])


def test_sarif_export():
    seed()
    r = client.get("/api/jobs/job1/export/sarif")
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == "2.1.0"
    result = body["runs"][0]["results"][0]
    assert result["ruleId"] == "CWE-798" and result["level"] == "warning"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_pdf_export():
    seed()
    r = client.get("/api/jobs/job1/export/pdf")
    assert r.status_code == 200
    assert r.content.startswith(b"%PDF")
    assert r.headers["content-type"] == "application/pdf"


def test_export_errors():
    assert client.get("/api/jobs/nope/export/sarif").status_code == 404
    seed("running1", status="running")
    assert client.get("/api/jobs/running1/export/pdf").status_code == 409