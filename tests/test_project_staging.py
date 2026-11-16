from pathlib import Path

from agent.patches.sandbox import SandboxResult
from agent.patches.staging import validate_patch_in_project


class FakeRunner:
    def __init__(self, status="passed", stdout="", stderr=""):
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.workspace = None
        self.command = None
        self.project_test_exists = False
        self.staged_source = None

    def run(self, workspace_dir, command):
        self.workspace = Path(workspace_dir)
        self.command = command

        # Inspect the temporary project while it still exists.
        self.project_test_exists = (
            self.workspace / "tests" / "test_app.py"
        ).exists()

        source = self.workspace / "src" / "app.py"
        if source.exists():
            self.staged_source = source.read_text(encoding="utf-8")

        return SandboxResult(
            status=self.status,
            exit_code=0 if self.status == "passed" else 1,
            stdout=self.stdout,
            stderr=self.stderr,
        )


def _diff(old, new, filename="src/app.py"):
    import difflib
    return "".join(difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    ))


def test_project_staging_copies_full_project_and_preserves_original(tmp_path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "tests").mkdir()

    original = "VALUE = 1\n"
    (project / "src" / "app.py").write_text(original, encoding="utf-8")
    (project / "tests" / "test_app.py").write_text(
        "from src.app import VALUE\n", encoding="utf-8"
    )

    runner = FakeRunner()
    result = validate_patch_in_project(
        project,
        _diff(original, "VALUE = 2\n"),
        "src/app.py",
        runner,
        ["python", "-m", "pytest", "-q"],
    )

    assert result.accepted is True
    assert (project / "src" / "app.py").read_text(encoding="utf-8") == original
    assert runner.project_test_exists is True
    assert runner.staged_source == "VALUE = 2\n"


def test_project_staging_reports_missing_dependency_as_not_runnable(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    original = "VALUE = 1\n"
    (project / "app.py").write_text(original, encoding="utf-8")

    runner = FakeRunner(
        status="failed",
        stderr="ModuleNotFoundError: No module named 'third_party_lib'",
    )

    result = validate_patch_in_project(
        project,
        _diff(original, "VALUE = 2\n", "app.py"),
        "app.py",
        runner,
        ["python", "-m", "pytest", "-q"],
    )

    assert result.accepted is False
    assert result.tests_runnable is False
    assert any("Tests not runnable" in error for error in result.errors)


def test_backend_payload_omits_updated_source_and_is_json_serializable(tmp_path):
    import json

    project = tmp_path / "project"
    project.mkdir()

    original = "VALUE = 1\n"
    (project / "app.py").write_text(original, encoding="utf-8")

    result = validate_patch_in_project(
        project,
        _diff(original, "VALUE = 2\n", "app.py"),
        "app.py",
        FakeRunner(),
        ["python", "-m", "pytest", "-q"],
    )

    payload = result.to_backend_dict()
    assert "updated_source" not in payload["validation"]
    json.dumps(payload)
