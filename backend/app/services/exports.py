from datetime import datetime, timezone
from typing import List

from fpdf import FPDF

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
ORDER = ["critical", "high", "medium", "low", "info"]


def to_sarif(job: dict, findings: List[dict]) -> dict:
    """SARIF 2.1.0, readable by GitHub code scanning and the VS Code SARIF viewer."""
    rules = {}
    results = []
    for f in findings:
        rule_id = f.get("cwe_id") or "UNCLASSIFIED"
        if rule_id not in rules:
            rule = {"id": rule_id, "name": rule_id, "shortDescription": {"text": f["message"]}}
            if rule_id.startswith("CWE-") and rule_id[4:].isdigit():
                rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{rule_id[4:]}.html"
            rules[rule_id] = rule
        line_range = f.get("line_range") or {}
        region = {"startLine": f["line_number"], "endLine": line_range.get("end", f["line_number"])}
        if f.get("evidence"):
            region["snippet"] = {"text": f["evidence"]}
        results.append({
            "ruleId": rule_id,
            "level": LEVEL.get(f["severity"], "warning"),
            "message": {"text": f"{f['message']}: {f['explanation']}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file_path"]},
                "region": region,
            }}],
            "properties": {
                "confidence": f["confidence"],
                "source": f["source"],
                "findingId": f["finding_id"],
                "remediation": f.get("suggested_remediation"),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AI Code Auditor", "version": "0.1.0", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def _t(value) -> str:
    # The built-in PDF fonts only support latin-1, so replace anything else.
    return str(value or "").encode("latin-1", "replace").decode("latin-1")


def _para(pdf: FPDF, text: str, h: float = 5) -> None:
    pdf.multi_cell(0, h, _t(text), new_x="LMARGIN", new_y="NEXT")


def to_pdf(job: dict, findings: List[dict]) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    _para(pdf, "AI Code Auditor - Security Report", 10)
    pdf.set_font("Helvetica", "", 10)
    _para(pdf, f"Source: {job['source']} ({job['source_type']})")
    _para(pdf, f"Job: {job['job_id']}   Files scanned: {job.get('files_scanned', 0)}")
    _para(pdf, f"Created: {job.get('created_at', '')}   Report: {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC")
    pdf.ln(3)

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ORDER}
    pdf.set_font("Helvetica", "B", 12)
    _para(pdf, f"Summary: {len(findings)} finding(s)", 7)
    pdf.set_font("Helvetica", "", 10)
    _para(pdf, "   ".join(f"{s}: {n}" for s, n in counts.items()))
    pdf.ln(3)

    ranked = sorted(findings, key=lambda f: ORDER.index(f["severity"]) if f["severity"] in ORDER else 99)
    for f in ranked:
        pdf.set_font("Helvetica", "B", 11)
        _para(pdf, f"[{f['severity'].upper()}] {f['message']}", 6)
        pdf.set_font("Helvetica", "", 10)
        _para(pdf, f"{f.get('cwe_id') or 'No CWE'}  |  {f['file_path']}:{f['line_number']}  |  confidence {f['confidence']}")
        _para(pdf, f["explanation"])
        if f.get("evidence"):
            pdf.set_font("Courier", "", 9)
            _para(pdf, f["evidence"][:300])
            pdf.set_font("Helvetica", "", 10)
        if f.get("suggested_remediation"):
            _para(pdf, f"Remediation: {f['suggested_remediation']}")
        pdf.ln(3)
    if not findings:
        _para(pdf, "No findings. Note: only Python files are scanned for now.")
    return bytes(pdf.output())