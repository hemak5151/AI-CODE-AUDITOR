
import subprocess
from unittest.mock import patch

import pytest

from agent.patches.sandbox import DockerSandboxRunner


def completed_process(args, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=args,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_sandbox_builds_restricted_docker_command(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim",
        memory_limit="512m",
        cpu_limit=1.0,
        pids_limit=64,
        timeout_seconds=30,
    )

    with patch(
        "agent.patches.sandbox.subprocess.run"
    ) as mocked_run:

        mocked_run.return_value = completed_process(
            args=["docker", "run"],
            returncode=0,
            stdout="Sandbox completed.",
        )

        result = runner.run(
            workspace_dir=tmp_path,
            command=["python", "--version"],
        )

    assert result.status == "passed"
    assert result.exit_code == 0
    assert "Sandbox completed." in result.stdout

    docker_args = mocked_run.call_args.args[0]

    assert "--network" in docker_args
    assert docker_args[docker_args.index("--network") + 1] == "none"

    assert "--memory" in docker_args
    assert docker_args[docker_args.index("--memory") + 1] == "512m"

    assert "--cpus" in docker_args
    assert "--pids-limit" in docker_args

    assert "--read-only" in docker_args
    assert "--cap-drop" in docker_args
    assert "--security-opt" in docker_args

    mount_argument = docker_args[
        docker_args.index("--mount") + 1
    ]

    assert str(tmp_path.resolve()) in mount_argument
    assert "readonly" in mount_argument

    assert mocked_run.call_args.kwargs["timeout"] == 30


def test_sandbox_returns_failed_for_nonzero_exit(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim"
    )

    with patch(
        "agent.patches.sandbox.subprocess.run"
    ) as mocked_run:

        mocked_run.return_value = completed_process(
            args=["docker", "run"],
            returncode=1,
            stdout="",
            stderr="Test failed.",
        )

        result = runner.run(
            workspace_dir=tmp_path,
            command=["python", "test_example.py"],
        )

    assert result.status == "failed"
    assert result.exit_code == 1
    assert "Test failed." in result.stderr


def test_sandbox_reports_docker_unavailable(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim"
    )

    with patch(
        "agent.patches.sandbox.subprocess.run",
        side_effect=FileNotFoundError,
    ):
        result = runner.run(
            workspace_dir=tmp_path,
            command=["python", "--version"],
        )

    assert result.status == "unavailable"
    assert any(
        "Docker CLI was not found" in error
        for error in result.errors
    )


def test_sandbox_handles_timeout_and_attempts_cleanup(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim",
        timeout_seconds=2,
    )

    timeout_error = subprocess.TimeoutExpired(
        cmd=["docker", "run"],
        timeout=2,
        output=b"Partial output",
        stderr=b"Execution timed out",
    )

    with patch(
        "agent.patches.sandbox.subprocess.run"
    ) as mocked_run:

        mocked_run.side_effect = [
            timeout_error,
            completed_process(
                args=["docker", "rm"],
                returncode=0,
            ),
        ]

        result = runner.run(
            workspace_dir=tmp_path,
            command=["python", "slow_test.py"],
        )

    assert result.status == "timeout"
    assert result.stdout == "Partial output"
    assert result.stderr == "Execution timed out"

    assert mocked_run.call_count == 2

    cleanup_args = mocked_run.call_args_list[1].args[0]

    assert cleanup_args[:3] == [
        "docker",
        "rm",
        "--force",
    ]


def test_sandbox_rejects_empty_command(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim"
    )

    with pytest.raises(ValueError, match="non-empty"):
        runner.run(
            workspace_dir=tmp_path,
            command=[],
        )


def test_sandbox_rejects_string_command(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim"
    )

    with pytest.raises(ValueError, match="non-empty"):
        runner.run(
            workspace_dir=tmp_path,
            command="python --version",
        )


def test_sandbox_rejects_nonexistent_workspace(tmp_path):
    runner = DockerSandboxRunner(
        image="python:3.13-slim"
    )

    missing_workspace = tmp_path / "does-not-exist"

    with pytest.raises(ValueError, match="Invalid sandbox workspace"):
        runner.run(
            workspace_dir=missing_workspace,
            command=["python", "--version"],
        )


def test_sandbox_rejects_invalid_resource_limits():
    with pytest.raises(ValueError):
        DockerSandboxRunner(
            image="python:3.13-slim",
            cpu_limit=0,
        )

    with pytest.raises(ValueError):
        DockerSandboxRunner(
            image="python:3.13-slim",
            memory_limit="invalid",
        )

    with pytest.raises(ValueError):
        DockerSandboxRunner(
            image="python:3.13-slim",
            pids_limit=0,
        )


def test_sandbox_rejects_invalid_image_name():
    with pytest.raises(ValueError):
        DockerSandboxRunner(
            image="python image with spaces",
        )
