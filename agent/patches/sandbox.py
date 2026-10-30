
import re
import subprocess
import uuid

from pathlib import Path
from typing import Literal, Sequence

from pydantic import BaseModel


class SandboxResult(BaseModel):
    """Outcome of an isolated Docker execution."""

    status: Literal["passed", "failed", "timeout", "unavailable"]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    errors: list[str] = []


class DockerSandboxRunner:
    """
    Run commands in a restricted Docker container.

    The workspace must be a disposable staging directory, never
    the original project repository.
    """

    def __init__(
        self,
        image: str,
        memory_limit: str = "512m",
        cpu_limit: float = 1.0,
        pids_limit: int = 64,
        timeout_seconds: int = 30,
    ):
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._/:@-]*",
            image,
        ):
            raise ValueError("Invalid Docker image name.")

        if not re.fullmatch(r"[1-9][0-9]*[kmgKMG]?", memory_limit):
            raise ValueError("Invalid memory limit.")

        if not 0 < cpu_limit <= 2:
            raise ValueError("CPU limit must be greater than 0 and at most 2.")

        if pids_limit < 1:
            raise ValueError("PID limit must be positive.")

        if timeout_seconds < 1:
            raise ValueError("Timeout must be at least one second.")

        self.image = image
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.pids_limit = pids_limit
        self.timeout_seconds = timeout_seconds

    def _remove_container(self, container_name: str) -> None:
        """Attempt to remove a container left behind after a timeout."""

        try:
            subprocess.run(
                [
                    "docker",
                    "rm",
                    "--force",
                    container_name,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def run(
        self,
        workspace_dir: Path,
        command: Sequence[str],
    ) -> SandboxResult:
        """
        Execute a command with restricted networking, privileges,
        resources and filesystem access.

        Only the supplied workspace is mounted, and it is read-only.
        Temporary writable storage is restricted to /tmp inside
        the container.
        """

        if isinstance(command, (str, bytes)) or not command:
            raise ValueError(
                "Command must be a non-empty sequence of arguments."
            )

        if not all(
            isinstance(arg, str) and arg and "\x00" not in arg
            for arg in command
        ):
            raise ValueError("Invalid command arguments.")

        try:
            workspace = Path(workspace_dir).resolve(strict=True)

            if not workspace.is_dir():
                raise ValueError("Workspace must be an existing directory.")

        except (OSError, RuntimeError) as exc:
            raise ValueError(f"Invalid sandbox workspace: {exc}") from exc

        container_name = f"auditor-sandbox-{uuid.uuid4().hex[:12]}"

        docker_command = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,

            # No network access.
            "--network",
            "none",

            # Resource restrictions.
            "--memory",
            self.memory_limit,
            "--cpus",
            str(self.cpu_limit),
            "--pids-limit",
            str(self.pids_limit),

            # Restrict container privileges.
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--user",
            "65534:65534",

            # Make the container root filesystem read-only.
            "--read-only",

            # Provide limited temporary writable storage.
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",

            # Make the supplied workspace available read-only.
            "--mount",
            (
                f"type=bind,source={workspace},"
                "target=/workspace,readonly"
            ),

            "--workdir",
            "/workspace",

            # Reduce unnecessary Python filesystem writes.
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",

            # Use the configured, trusted image.
            self.image,

            *command,
        ]

        try:
            completed = subprocess.run(
                docker_command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )

            return SandboxResult(
                status=(
                    "passed"
                    if completed.returncode == 0
                    else "failed"
                ),
                exit_code=completed.returncode,
                stdout=completed.stdout[-10000:],
                stderr=completed.stderr[-10000:],
            )

        except FileNotFoundError:
            return SandboxResult(
                status="unavailable",
                errors=[
                    "Docker CLI was not found. "
                    "Install and configure Docker before execution."
                ],
            )

        except subprocess.TimeoutExpired as exc:
            self._remove_container(container_name)

            stdout = exc.stdout or ""
            stderr = exc.stderr or ""

            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")

            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")

            return SandboxResult(
                status="timeout",
                stdout=stdout[-10000:],
                stderr=stderr[-10000:],
                errors=[
                    f"Sandbox exceeded its {self.timeout_seconds}-second timeout."
                ],
            )

        except OSError as exc:
            self._remove_container(container_name)

            return SandboxResult(
                status="failed",
                errors=[f"Docker execution error: {exc}"],
            )
