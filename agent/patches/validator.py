
import ast
import subprocess
import tempfile

from pathlib import Path, PurePosixPath, PureWindowsPath

from pydantic import BaseModel, Field


class PatchValidationResult(BaseModel):
    """Result of deterministic patch validation."""

    valid: bool
    applied: bool = False
    python_syntax_valid: bool | None = None
    errors: list[str] = Field(default_factory=list)
    updated_source: str | None = None


def _normalise_safe_path(value: str) -> str:
    value = value.replace("\\", "/").strip()

    if not value or "\x00" in value:
        raise ValueError("Patch contains an empty or invalid path.")

    windows_path = PureWindowsPath(value)
    posix_path = PurePosixPath(value)

    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or ".." in value.split("/")
        or posix_path.as_posix() == "."
    ):
        raise ValueError(f"Unsafe patch path rejected: {value}")

    return posix_path.as_posix()


def _read_patch_headers(
    diff_text: str,
) -> tuple[str, str, int]:
    """Read a single-file unified diff and determine Git path stripping."""

    lines = diff_text.splitlines()

    old_headers = [
        i for i, line in enumerate(lines)
        if line.startswith("--- ")
    ]
    new_headers = [
        i for i, line in enumerate(lines)
        if line.startswith("+++ ")
    ]

    if len(old_headers) != 1 or len(new_headers) != 1:
        raise ValueError(
            "Expected exactly one original and one modified file header."
        )

    old_index = old_headers[0]
    new_index = new_headers[0]

    if new_index <= old_index:
        raise ValueError("Invalid unified diff header order.")

    if not any(
        line.startswith("@@ ")
        for line in lines[new_index + 1:]
    ):
        raise ValueError("Missing unified diff hunk header (@@).")

    old_path = lines[old_index][4:].split("\t", 1)[0].strip()
    new_path = lines[new_index][4:].split("\t", 1)[0].strip()

    # Standard Git format: a/file.py and b/file.py
    if old_path.startswith("a/") and new_path.startswith("b/"):
        strip_level = 1
        old_path = old_path[2:]
        new_path = new_path[2:]

    # Existing project diff utility: file.py and file.py
    elif not old_path.startswith(("a/", "b/")) and (
        not new_path.startswith(("a/", "b/"))
    ):
        strip_level = 0

    else:
        raise ValueError("Inconsistent unified diff path prefixes.")

    return (
        _normalise_safe_path(old_path),
        _normalise_safe_path(new_path),
        strip_level,
    )


def validate_unified_diff(
    original_source: str,
    diff_text: str,
    expected_file_path: str,
) -> PatchValidationResult:
    """Validate and apply a patch only inside a temporary directory."""

    if not original_source:
        return PatchValidationResult(
            valid=False,
            errors=["Original source code is empty."],
        )

    if not diff_text or not diff_text.strip():
        return PatchValidationResult(
            valid=False,
            errors=["Unified diff is empty."],
        )

    try:
        expected_path = _normalise_safe_path(expected_file_path)

        old_path, new_path, strip_level = _read_patch_headers(diff_text)

        if old_path != expected_path or new_path != expected_path:
            raise ValueError(
                "Patch file paths do not match the expected source file."
            )

    except ValueError as exc:
        return PatchValidationResult(valid=False, errors=[str(exc)])

    try:
        with tempfile.TemporaryDirectory(
            prefix="ai-code-auditor-patch-"
        ) as temporary_directory:

            root = Path(temporary_directory)

            target_file = root.joinpath(
                *PurePosixPath(expected_path).parts
            )

            target_file.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            target_file.write_text(
                original_source,
                encoding="utf-8",
            )

            patch_file = root / "proposal.diff"

            patch_file.write_text(
                diff_text,
                encoding="utf-8",
                newline="\n",
            )

            git_prefix = f"-p{strip_level}"

            check = subprocess.run(
                [
                    "git",
                    "apply",
                    "--check",
                    "--whitespace=error",
                    git_prefix,
                    "proposal.diff",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            if check.returncode != 0:
                detail = check.stderr.strip() or check.stdout.strip()

                return PatchValidationResult(
                    valid=False,
                    errors=[
                        "Patch cannot be applied to the original source.",
                        detail,
                    ],
                )

            applied = subprocess.run(
                [
                    "git",
                    "apply",
                    "--whitespace=error",
                    git_prefix,
                    "proposal.diff",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )

            if applied.returncode != 0:
                detail = (
                    applied.stderr.strip() or applied.stdout.strip()
                )

                return PatchValidationResult(
                    valid=False,
                    errors=["Patch application failed.", detail],
                )

            updated_source = target_file.read_text(encoding="utf-8")

            syntax_valid = None
            errors = []

            if target_file.suffix.lower() == ".py":
                try:
                    ast.parse(updated_source, filename=expected_path)
                    syntax_valid = True
                except SyntaxError as exc:
                    syntax_valid = False
                    errors.append(f"Python syntax error: {exc}")

            return PatchValidationResult(
                valid=not errors,
                applied=True,
                python_syntax_valid=syntax_valid,
                errors=errors,
                updated_source=updated_source,
            )

    except FileNotFoundError:
        return PatchValidationResult(
            valid=False,
            errors=["Git executable was not found on PATH."],
        )

    except subprocess.TimeoutExpired:
        return PatchValidationResult(
            valid=False,
            errors=["Patch validation timed out."],
        )

    except OSError as exc:
        return PatchValidationResult(
            valid=False,
            errors=[f"Temporary validation failed: {exc}"],
        )
