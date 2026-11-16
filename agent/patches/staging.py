"""Safe project staging and patch validation for Member 3."""
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Sequence

from pydantic import BaseModel, Field

from agent.patches.validator import PatchValidationResult, validate_unified_diff
from agent.patches.sandbox import DockerSandboxRunner, SandboxResult


class StagingResult(BaseModel):
    """Combined static validation and sandbox execution result."""
    accepted: bool
    validation: PatchValidationResult
    execution: SandboxResult | None = None
    errors: list[str] = Field(default_factory=list)
    tests_runnable: bool = True

    def to_backend_dict(self) -> dict:
        """Return a JSON-safe payload without the potentially large updated source."""
        validation_data = self.validation.model_dump(
            mode="json", exclude={"updated_source"}
        )
        execution_data = (
            self.execution.model_dump(mode="json")
            if self.execution is not None
            else None
        )
        return {
            "accepted": self.accepted,
            "validation": validation_data,
            "sandbox": execution_data,
            "tests_runnable": self.tests_runnable,
            "errors": list(self.errors),
        }


def _validate_command(command: Sequence[str]) -> None:
    if isinstance(command, (str, bytes)) or not command:
        raise ValueError("Command must be a non-empty sequence of arguments.")
    if not all(isinstance(arg, str) and arg and "\x00" not in arg for arg in command):
        raise ValueError("Invalid command arguments.")


def _is_missing_dependency(execution: SandboxResult) -> bool:
    output = f"{execution.stdout}\n{execution.stderr}".lower()
    return (
        "modulenotfounderror" in output
        or "no module named" in output
        or "cannot import name" in output
    )


def validate_and_run_patch(
    original_source: str,
    diff_text: str,
    expected_file_path: str,
    runner: DockerSandboxRunner,
    command: Sequence[str],
) -> StagingResult:
    """Legacy single-file staging API; retained for backward compatibility."""
    _validate_command(command)
    validation = validate_unified_diff(
        original_source=original_source,
        diff_text=diff_text,
        expected_file_path=expected_file_path,
    )

    if not validation.valid or validation.updated_source is None:
        return StagingResult(
            accepted=False,
            validation=validation,
            errors=[
                "Patch failed deterministic validation. "
                "Sandbox execution was skipped."
            ],
        )

    try:
        relative_path = PurePosixPath(expected_file_path)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise ValueError("Expected file path must be a safe relative path.")

        with tempfile.TemporaryDirectory(prefix="ai-code-auditor-staging-") as temp:
            workspace = Path(temp)
            target_file = workspace.joinpath(*relative_path.parts)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(validation.updated_source, encoding="utf-8")

            execution = runner.run(workspace_dir=workspace, command=command)
            passed = execution.status == "passed"
            missing_dependency = _is_missing_dependency(execution)

            errors = []
            if missing_dependency:
                errors.append(
                    "Tests not runnable: a required third-party dependency "
                    "is not installed in the offline sandbox image."
                )
            elif not passed:
                errors.append(
                    "Sandbox execution did not pass. Patch acceptance was denied."
                )

            return StagingResult(
                accepted=passed,
                validation=validation,
                execution=execution,
                errors=errors,
                tests_runnable=not missing_dependency,
            )
    except OSError as exc:
        return StagingResult(
            accepted=False,
            validation=validation,
            errors=[f"Could not prepare disposable staging workspace: {exc}"],
        )


def validate_patch_in_project(
    project_dir: Path,
    diff_text: str,
    expected_file_path: str,
    runner: DockerSandboxRunner,
    command: Sequence[str],
) -> StagingResult:
    """
    Copy the complete project to a temporary directory, validate and apply the
    proposed source to that copy, then execute tests in the isolated sandbox.
    The original project is never modified.
    """
    _validate_command(command)

    try:
        project = Path(project_dir).resolve(strict=True)
        if not project.is_dir():
            raise ValueError("project_dir must be an existing directory.")

        relative_path = PurePosixPath(expected_file_path)
        if (
            not expected_file_path
            or "\\" in expected_file_path
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or ":" in expected_file_path
        ):
            raise ValueError(
                "expected_file_path must be a safe relative path using forward slashes."
            )

        original_file = project.joinpath(*relative_path.parts).resolve(strict=True)
        if not original_file.is_file() or not original_file.is_relative_to(project):
            raise ValueError("Expected patch target must be a file inside project_dir.")

        original_source = original_file.read_text(encoding="utf-8")
        validation = validate_unified_diff(
            original_source=original_source,
            diff_text=diff_text,
            expected_file_path=expected_file_path,
        )

        if not validation.valid or validation.updated_source is None:
            return StagingResult(
                accepted=False,
                validation=validation,
                errors=[
                    "Patch failed deterministic validation. "
                    "Sandbox execution was skipped."
                ],
            )

        ignored = shutil.ignore_patterns(
            ".git", "__pycache__", ".pytest_cache", ".mypy_cache",
            ".ruff_cache", ".venv", "venv", "node_modules"
        )

        with tempfile.TemporaryDirectory(prefix="ai-code-auditor-project-") as temp:
            staged_project = Path(temp) / "project"
            shutil.copytree(project, staged_project, ignore=ignored)

            staged_target = staged_project.joinpath(*relative_path.parts)
            staged_target.write_text(validation.updated_source, encoding="utf-8")

            execution = runner.run(
                workspace_dir=staged_project,
                command=command,
            )
            passed = execution.status == "passed"
            missing_dependency = _is_missing_dependency(execution)

            errors = []
            if missing_dependency:
                errors.append(
                    "Tests not runnable: a required third-party dependency "
                    "is not installed in the offline sandbox image. "
                    "Bake the dependency into the sandbox image and retry."
                )
            elif execution.status == "unavailable":
                errors.append(
                    "Tests not runnable: Docker sandbox is unavailable."
                )
            elif not passed:
                errors.append(
                    "Sandbox execution did not pass. Patch acceptance was denied."
                )

            return StagingResult(
                accepted=passed,
                validation=validation,
                execution=execution,
                errors=errors,
                tests_runnable=not missing_dependency
                and execution.status != "unavailable",
            )

    except (OSError, RuntimeError, ValueError) as exc:
        # A validation result is required by the public result contract. If the
        # project cannot be opened, return a synthetic failed validation result.
        from agent.patches.validator import PatchValidationResult
        failed_validation = PatchValidationResult(
            valid=False,
            applied=False,
            python_syntax_valid=False,
            errors=[f"Could not stage project: {exc}"],
            updated_source=None,
        )
        return StagingResult(
            accepted=False,
            validation=failed_validation,
            errors=[f"Could not stage project: {exc}"],
            tests_runnable=False,
        )
