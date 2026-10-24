from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_sample_when_folder_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_RESULTS_DIR", str(tmp_path))
    body = client.get("/api/results").json()
    assert body["sample"] is True and len(body["rows"]) == 20


def test_starter_example_is_not_treated_as_real(tmp_path, monkeypatch):
    (tmp_path / "example.csv").write_text("run_id,dataset,precision,recall,f1\nstarter-001,examples,1.0,1.0,1.0\n")
    monkeypatch.setenv("AUDITOR_RESULTS_DIR", str(tmp_path))
    assert client.get("/api/results").json()["sample"] is True


def test_real_rows_are_loaded_and_bad_rows_skipped(tmp_path, monkeypatch):
    (tmp_path / "run1.csv").write_text(
        "config,cwe,precision,recall,f1,fpr,n\n"
        "C1,ALL,0.5,0.4,0.44,0.1,100\n"
        "C2,ALL,abc,0.4,0.44,0.1,100\n"
        "C9,ALL,0.5,0.4,0.44,0.1,100\n"
    )
    monkeypatch.setenv("AUDITOR_RESULTS_DIR", str(tmp_path))
    body = client.get("/api/results").json()
    assert body["sample"] is False and body["files"] == ["run1.csv"]
    assert len(body["rows"]) == 1 and body["rows"][0]["config"] == "C1" and body["rows"][0]["n"] == 100.0


def test_missing_folder_gives_sample(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_RESULTS_DIR", str(tmp_path / "nope"))
    assert client.get("/api/results").json()["sample"] is True