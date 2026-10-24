import csv
import os
from pathlib import Path
from typing import List, Optional

CONFIGS = ["C1", "C2", "C3", "C4", "C5"]
REQUIRED = {"config", "cwe", "precision", "recall", "f1"}


def results_dir() -> Path:
    default = Path(__file__).resolve().parents[3] / "evaluation" / "results"
    return Path(os.environ.get("AUDITOR_RESULTS_DIR", default))


def _num(value) -> Optional[float]:
    try:
        text = str(value).strip() if value is not None else ""
        return float(text) if text else None
    except ValueError:
        return None


def _read_csv(path: Path) -> List[dict]:
    rows: List[dict] = []
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames or not REQUIRED.issubset(set(reader.fieldnames)):
                return rows
            for r in reader:
                config = (r.get("config") or "").strip().upper()
                precision, recall, f1 = _num(r.get("precision")), _num(r.get("recall")), _num(r.get("f1"))
                if config not in CONFIGS or None in (precision, recall, f1):
                    continue
                rows.append({
                    "config": config,
                    "cwe": (r.get("cwe") or "ALL").strip() or "ALL",
                    "precision": precision, "recall": recall, "f1": f1,
                    "fpr": _num(r.get("fpr")), "n": _num(r.get("n")),
                    "f1_lo": _num(r.get("f1_lo")), "f1_hi": _num(r.get("f1_hi")),
                })
    except OSError:
        return []
    return rows


def sample_rows() -> List[dict]:
    """Placeholder numbers so the dashboard can be built. NOT real results."""
    base_f1 = {"C1": 0.40, "C2": 0.45, "C3": 0.52, "C4": 0.58, "C5": 0.63}
    offsets = {"ALL": 0.0, "CWE-89": 0.05, "CWE-78": -0.04, "CWE-798": 0.08}
    rows = []
    for i, config in enumerate(CONFIGS):
        for cwe, off in offsets.items():
            f1 = min(1.0, max(0.0, base_f1[config] + off))
            rows.append({
                "config": config, "cwe": cwe,
                "precision": round(min(1.0, f1 + 0.03), 2), "recall": round(max(0.0, f1 - 0.03), 2),
                "f1": round(f1, 2), "fpr": round(0.30 - 0.05 * i, 2), "n": 0,
                "f1_lo": None, "f1_hi": None,
            })
    return rows


def load_results() -> dict:
    folder = results_dir()
    rows: List[dict] = []
    files: List[str] = []
    if folder.is_dir():
        for path in sorted(folder.glob("*.csv")):
            found = _read_csv(path)
            if found:
                files.append(path.name)
                rows.extend(found)
    if rows:
        return {"sample": False, "files": files, "rows": rows}
    return {"sample": True, "files": [], "rows": sample_rows()}