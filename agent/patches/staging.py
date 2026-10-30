
import tempfile

from pathlib import Path, PurePosixPath
from typing import Sequence

from pydantic import BaseModel

from agent.patches.validator import (
    PatchValidationResult,
    validate_unified_diff,
)
from agent.patches.sandbox import (
    DockerSandboxRunner,
    SandboxResult,
)


class StagingResult(BaseModel):
    """Combined static validation and sandbox execution result."""

    accepted: bool
    validation: PatchValidationResult
    execution: SandboxResult | None = None
    errors: list[str] = []


def validate_and_run_patch(
    original_source: str,
    diff_text: str,
    expected_file_path: str,
    runner: DockerSandboxRunner,
    command: Sequence[str],
) -> StagingResult:
    """
    Validate a patch, stage its modified source in a disposable
    directory, and execute the supplied command through the runner.

    The original source and repository are never modified.
    """

    if isinstance(command, (str, bytes)) or not command:
        raise ValueError(
            "Command must be a non-empty sequence of arguments."
        )

    validation = validate_unified_diff(
        original_source=original_source,
        diff_text=diff_text,
        expected_file_path=expected_file_path,
    )

    # Invalid patches must never reach the sandbox.
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

        with tempfile.TemporaryDirectory(
            prefix="ai-code-auditor-staging-"
        ) as temporary_directory:

            workspace = Path(temporary_directory)

            target_file = workspace.joinpath(
                *relative_path.parts
            )

            target_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            target_file.write_text(
                validation.updated_source,
                encoding="utf-8",
            )

            # The runner mounts only this temporary workspace.
            execution = runner.run(
                workspace_dir=workspace,
                command=command,
            )

            passed = execution.status == "passed"

            return StagingResult(
                accepted=passed,
                validation=validation,
                execution=execution,
                errors=(
                    []
                    if passed
                    else [
                        "Sandbox execution did not pass. "
                        "Patch acceptance was denied."
                    ]
                ),
            )

    except OSError as exc:
        return StagingResult(
            accepted=False,
            validation=validation,
            errors=[
                f"Could not prepare disposable staging workspace: {exc}"
            ],
        )
