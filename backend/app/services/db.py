import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

ALLOWED_FIELDS = {"status", "progress", "message", "error", "files_scanned"}


def data_dir() -> Path:
    default = Path(__file__).resolve().parents[2] / "data"
    d = Path(os.environ.get("AUDITOR_DATA_DIR", default))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir() / "auditor.db")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS jobs ("
        "job_id TEXT PRIMARY KEY, source_type TEXT, source TEXT, status TEXT, "
        "progress INTEGER, message TEXT, error TEXT, files_scanned INTEGER DEFAULT 0, created_at TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, data TEXT)"
    )
    return conn


def create_job(job_id: str, source_type: str, source: str) -> None:
    with closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT INTO jobs (job_id, source_type, source, status, progress, message, files_scanned, created_at) "
            "VALUES (?, ?, ?, 'queued', 0, 'Queued', 0, ?)",
            (job_id, source_type, source, datetime.now(timezone.utc).isoformat()),
        )


def update_job(job_id: str, **fields) -> None:
    bad = set(fields) - ALLOWED_FIELDS
    if bad:
        raise ValueError(f"Unknown job fields: {bad}")
    sets = ", ".join(f"{k}=?" for k in fields)
    with closing(_connect()) as conn, conn:
        conn.execute(f"UPDATE jobs SET {sets} WHERE job_id=?", (*fields.values(), job_id))


def get_job(job_id: str) -> Optional[dict]:
    with closing(_connect()) as conn:
        row = conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def add_findings(job_id: str, findings: List[dict]) -> None:
    with closing(_connect()) as conn, conn:
        conn.executemany(
            "INSERT INTO findings (job_id, data) VALUES (?, ?)",
            [(job_id, json.dumps(f)) for f in findings],
        )


def get_findings(job_id: str) -> List[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute("SELECT data FROM findings WHERE job_id=? ORDER BY id", (job_id,)).fetchall()
    return [json.loads(r["data"]) for r in rows]