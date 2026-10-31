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
    log_path=tmp_path / "sandbox_failure.jsonl",
    generate_patch=True,
    sandbox_runner=runner,
    sandbox_command=["python", "--version"],
    max_repair_attempts=0,
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
        max_repair_attempts=0,
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
class RetrySequenceFakeProvider(SandboxWorkflowFakeProvider):
    """Return different revised source files for successive repair attempts."""

    def __init__(self, revised_sources):
        super().__init__()
        self.revised_sources = list(revised_sources)
        self.last_source = revised_sources[-1]
        self.refactor_calls = 0
        self.refactor_prompts = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        properties = (
            request.response_format or {}
        ).get("properties", {})

        if "revised_source" not in properties:
            return super().generate(request)

        self.call_count += 1
        self.refactor_calls += 1
        self.refactor_prompts.append(request.prompt)

        if self.revised_sources:
            revised_source = self.revised_sources.pop(0)
        else:
            revised_source = self.last_source

        response = {
            "revised_source": revised_source,
            "description": "Repair SQL injection vulnerability.",
        }

        return LLMResponse(
            content=json.dumps(response),
            model="test-model",
            tokens=25,
        )


INVALID_SOURCE_CODE = (
    'user_id = input("User ID: ")\n'
    'query = "SELECT * FROM users WHERE id = ?"\n'
    "cursor.execute(query, (user_id,))\n"
    "def broken(:\n"
)


def test_repair_loop_recovers_after_validation_failure(tmp_path):
    provider = RetrySequenceFakeProvider([
        INVALID_SOURCE_CODE,
        SAFE_SOURCE_CODE,
    ])

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "repair_success.jsonl",
        generate_patch=True,
        max_repair_attempts=1,
    )

    assert provider.refactor_calls == 2
    assert provider.call_count == 5

    assert result.repair_attempts == 1
    assert result.patch_accepted is True
    assert result.patch_validation.valid is True

    assert result.critic_review is not None
    assert result.critic_review.approved is True

    # Verify that the second attempt received validation feedback.
    assert "Previous repair feedback:" in provider.refactor_prompts[1]
    assert "Validator error:" in provider.refactor_prompts[1]


def test_repair_loop_stops_after_maximum_attempts(tmp_path):
    provider = RetrySequenceFakeProvider([
        INVALID_SOURCE_CODE,
    ])

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "repair_limit.jsonl",
        generate_patch=True,
        max_repair_attempts=3,
    )

    # One initial attempt plus three additional repairs.
    assert provider.refactor_calls == 4

    assert result.repair_attempts == 3
    assert result.patch_accepted is False
    assert result.output.patch is None
    assert result.critic_review is None