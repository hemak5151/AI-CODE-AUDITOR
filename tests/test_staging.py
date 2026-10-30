
from pathlib import Path

from agent.patches.diff import unified_diff
from agent.patches.sandbox import SandboxResult
from agent.patches.staging import validate_and_run_patch


ORIGINAL_CODE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id = " + user_id\n'
    "    return query\n"
)

SAFE_CODE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id = ?"\n'
    "    return query\n"
)


class FakeSandboxRunner:
    """Simulate sandbox execution without requiring Docker."""

    def __init__(self, status="passed"):
        self.status = status
        self.calls = 0
        self.staged_source = None
        self.workspace = None
        self.received_command = None

    def run(self, workspace_dir: Path, command):
        self.calls += 1

        self.workspace = Path(workspace_dir)

        source_file = self.workspace / "example.py"

        self.staged_source = source_file.read_text(
            encoding="utf-8"
        )

        self.received_command = list(command)

        return SandboxResult(
            status=self.status,
            exit_code=0 if self.status == "passed" else 1,
            stdout="Mock sandbox execution completed.",
            stderr="" if self.status == "passed" else "Test failed.",
        )


def test_validated_patch_is_staged_and_executed():
    runner = FakeSandboxRunner()

    diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="example.py",
    )

    result = validate_and_run_patch(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
        runner=runner,
        command=["python", "--version"],
    )

    assert result.accepted is True
    assert result.validation.valid is True
    assert result.validation.applied is True

    assert result.execution is not None
    assert result.execution.status == "passed"

    assert runner.calls == 1
    assert runner.staged_source == SAFE_CODE

    assert runner.received_command == [
        "python",
        "--version",
    ]

    # Original source remains unchanged.
    assert ORIGINAL_CODE != runner.staged_source

    # Temporary staging directory is removed after execution.
    assert not runner.workspace.exists()


def test_invalid_patch_never_reaches_sandbox():
    runner = FakeSandboxRunner()

    invalid_diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="different.py",
    )

    result = validate_and_run_patch(
        original_source=ORIGINAL_CODE,
        diff_text=invalid_diff,
        expected_file_path="example.py",
        runner=runner,
        command=["python", "--version"],
    )

    assert result.accepted is False
    assert result.validation.valid is False
    assert result.execution is None

    # Sandbox must not be called for an invalid patch.
    assert runner.calls == 0


def test_failed_sandbox_execution_rejects_patch():
    runner = FakeSandboxRunner(status="failed")

    diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="example.py",
    )

    result = validate_and_run_patch(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
        runner=runner,
        command=["python", "test_example.py"],
    )

    assert result.validation.valid is True
    assert result.execution is not None
    assert result.execution.status == "failed"

    # Static validation alone must not mean final acceptance.
    assert result.accepted is False

    assert runner.calls == 1
