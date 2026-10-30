import json
from pathlib import Path

from agent.agents.workflow import run_agent_workflow
from agent.models.contracts import AgentInput, LLMRequest, LLMResponse
from agent.models.provider import LLMProvider
from agent.patches.sandbox import SandboxResult
from shared.schemas.finding import Finding, Severity
from shared.schemas.interfaces import RetrievalResponse


SOURCE_CODE = (
    'user_id = input("User ID: ")\n'
    'query = "SELECT * FROM users WHERE id = " + user_id\n'
    "cursor.execute(query)\n"
)

SAFE_SOURCE_CODE = (
    'user_id = input("User ID: ")\n'
    'query = "SELECT * FROM users WHERE id = ?"\n'
    "cursor.execute(query, (user_id,))\n"
)


class SandboxWorkflowFakeProvider(LLMProvider):
    """Provide deterministic responses for the four agents."""

    def __init__(self):
        self.call_count = 0

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.call_count += 1

        properties = (
            request.response_format or {}
        ).get("properties", {})

        if "compliant" in properties:
            response = {
                "compliant": True,
                "confidence": 0.95,
                "reason": "The remediation follows the supplied guidance.",
                "guideline_reference": None,
                "recommended_action": "Use parameterized SQL.",
            }

        elif "revised_source" in properties:
            response = {
                "revised_source": SAFE_SOURCE_CODE,
                "description": (
                    "Replace SQL concatenation with a parameterized query."
                ),
            }

        elif "approved" in properties:
            response = {
                "approved": True,
                "confidence": 0.94,
                "issues": [],
                "explanation": (
                    "The patch uses parameterized SQL and addresses "
                    "the identified vulnerability."
                ),
                "recommended_changes": "None.",
            }

        elif "cwe_id" in properties:
            response = {
                "cwe_id": "CWE-89",
                "severity": "high",
                "confidence": 0.91,
                "message": "Potential SQL injection",
                "explanation": "User input is concatenated into SQL.",
                "line_number": 2,
                "evidence": (
                    'query = "SELECT * FROM users WHERE id = " + user_id'
                ),
                "suggested_remediation": "Use parameterized SQL queries.",
            }

        else:
            raise AssertionError(
                f"Unexpected response schema: {properties}"
            )

        return LLMResponse(
            content=json.dumps(response),
            model="test-model",
            tokens=25,
        )


class FakeSandboxRunner:
    """Simulate Docker execution without requiring Docker."""

    def __init__(self, status="passed"):
        self.status = status
        self.calls = 0
        self.staged_source = None
        self.workspace = None

    def run(self, workspace_dir: Path, command):
        self.calls += 1
        self.workspace = Path(workspace_dir)

        source_file = self.workspace / "example.py"

        self.staged_source = source_file.read_text(
            encoding="utf-8"
        )

        return SandboxResult(
            status=self.status,
            exit_code=0 if self.status == "passed" else 1,
            stdout="Mock sandbox completed.",
            stderr="" if self.status == "passed" else "Test execution failed.",
        )


def make_agent_input():
    finding = Finding(
        finding_id="sandbox-test-001",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        confidence=0.9,
        message="Potential SQL injection",
        explanation="User input is concatenated into an SQL query.",
        file_path="example.py",
        line_number=2,
        evidence=(
            'query = "SELECT * FROM users WHERE id = " + user_id'
        ),
        source="test",
        suggested_remediation="Use parameterized SQL.",
    )

    retrieval = RetrievalResponse(
        query="SQL injection prevention",
        chunks=[],
    )

    return AgentInput(
        finding=finding,
        retrieval=retrieval,
    )


def test_sandbox_enabled_workflow_accepts_successful_execution(tmp_path):
    provider = SandboxWorkflowFakeProvider()
    runner = FakeSandboxRunner(status="passed")

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "sandbox_success.jsonl",
        generate_patch=True,
        sandbox_runner=runner,
        sandbox_command=["python", "--version"],
    )

    # All four agents should execute.
    assert provider.call_count == 4

    # Static validation must succeed.
    assert result.patch_validation is not None
    assert result.patch_validation.valid is True

    # Staging and mocked sandbox execution must succeed.
    assert result.staging_result is not None
    assert result.staging_result.accepted is True
    assert result.staging_result.execution.status == "passed"

    # Critic must run after successful sandbox execution.
    assert result.critic_review is not None
    assert result.critic_review.approved is True

    # All acceptance conditions must be satisfied.
    assert result.patch_accepted is True
    assert result.output.patch is not None

    # Verify that the modified source reached the fake runner.
    assert runner.calls == 1
    assert "WHERE id = ?" in runner.staged_source
    assert "cursor.execute(query, (user_id,))" in runner.staged_source

    # Temporary workspace must be removed after execution.
    assert not runner.workspace.exists()


def test_failed_sandbox_execution_prevents_patch_acceptance(tmp_path):
    provider = SandboxWorkflowFakeProvider()
    runner = FakeSandboxRunner(status="failed")

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "sandbox_failure.jsonl",
        generate_patch=True,
        sandbox_runner=runner,
        sandbox_command=["python", "--version"],
    )

    # Detector, Guideline Checker and Refactor execute.
    # Critic must not be invoked after sandbox failure.
    assert provider.call_count == 3

    assert result.patch_validation.valid is True

    assert result.staging_result is not None
    assert result.staging_result.accepted is False
    assert result.staging_result.execution.status == "failed"

    assert result.critic_review is None

    # Failed runtime execution must prevent acceptance.
    assert result.patch_accepted is False
    assert result.output.patch is None

    assert runner.calls == 1