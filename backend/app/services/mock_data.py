from shared.schemas.finding import Finding, LineRange, Severity
from shared.schemas.interfaces import Patch

MOCK_FINDINGS = [
    Finding(
        finding_id="MOCK-1", cwe_id="CWE-89", severity=Severity.HIGH, confidence=0.91,
        message="Possible SQL injection",
        explanation="User input is concatenated into a SQL query string.",
        file_path="app/db.py", line_number=12, line_range=LineRange(start=12, end=12),
        evidence='cur.execute("SELECT * FROM users WHERE id=" + uid)',
        source="mock", suggested_remediation="Use parameterized queries.",
    ),
    Finding(
        finding_id="MOCK-2", cwe_id="CWE-78", severity=Severity.CRITICAL, confidence=0.88,
        message="Possible command injection",
        explanation="shell=True with a string built from user input.",
        file_path="app/utils.py", line_number=30, line_range=LineRange(start=30, end=30),
        evidence='subprocess.run("ls " + path, shell=True)',
        source="mock", suggested_remediation="Pass an argument list and drop shell=True.",
    ),
    Finding(
        finding_id="MOCK-3", cwe_id="CWE-798", severity=Severity.MEDIUM, confidence=0.97,
        message="Hardcoded secret",
        explanation="A credential is stored directly in source code.",
        file_path="app/config.py", line_number=4, line_range=LineRange(start=4, end=4),
        evidence='API_KEY = "sk-demo-123"', source="mock",
        suggested_remediation="Load the secret from an environment variable.",
    ),
]

MOCK_PATCHES = {
    "MOCK-1": Patch(
        finding_id="MOCK-1",
        description="Replace string concatenation with a parameterized query.",
        unified_diff=(
            "--- a/app/db.py\n+++ b/app/db.py\n@@ -12 +12 @@\n"
            '-cur.execute("SELECT * FROM users WHERE id=" + uid)\n'
            '+cur.execute("SELECT * FROM users WHERE id=?", (uid,))\n'
        ),
    ),
}