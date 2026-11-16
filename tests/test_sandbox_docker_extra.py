import os
import pytest
from pathlib import Path

from agent.patches.sandbox import DockerSandboxRunner


pytestmark = pytest.mark.docker


@pytest.fixture
def docker_runner():
    return DockerSandboxRunner(
        image=os.getenv("SANDBOX_IMAGE", "python:3.12-slim"),
        memory_limit=os.getenv("SANDBOX_MEMORY_LIMIT", "512m"),
        cpu_limit=float(os.getenv("SANDBOX_CPU_LIMIT", "1")),
        timeout_seconds=int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "30")),
    )


def test_docker_normal_command_can_read_workspace(tmp_path, docker_runner):
    (tmp_path / "probe.txt").write_text("workspace-ok", encoding="utf-8")
    result = docker_runner.run(
        tmp_path,
        ["python", "-c",
         "from pathlib import Path; "
         "assert Path('/workspace/probe.txt').read_text() == 'workspace-ok'"]
    )
    assert result.status == "passed"
    assert result.exit_code == 0


def test_docker_workspace_is_read_only(tmp_path, docker_runner):
    (tmp_path / "probe.txt").write_text("original", encoding="utf-8")
    result = docker_runner.run(
        tmp_path,
        ["python", "-c",
         "from pathlib import Path; "
         "Path('/workspace/probe.txt').write_text('modified')"]
    )
    assert result.status == "failed"
    assert (tmp_path / "probe.txt").read_text(encoding="utf-8") == "original"
