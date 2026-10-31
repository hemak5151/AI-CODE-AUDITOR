import json

from agent.agents.workflow import run_agent_workflow
from agent.models.contracts import AgentInput, LLMRequest, LLMResponse
from agent.models.provider import LLMProvider
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


class RepairWorkflowFakeProvider(LLMProvider):
    """Provide deterministic responses for all four agents."""

    def __init__(self, patch_mode="valid"):
        self.call_count = 0
        self.patch_mode = patch_mode

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
                "guideline_reference": "test-guide.md#SQL",
                "recommended_action": "Use parameterized SQL.",
            }

        elif "revised_source" in properties:
            if self.patch_mode == "no_change":
                revised_source = SOURCE_CODE
                description = (
                    "No source changes were made."
                )
            else:
                revised_source = SAFE_SOURCE_CODE
                description = (
                    "Use parameterized SQL to prevent SQL injection."
                )

            response = {
                "revised_source": revised_source,
                "description": description,
            }

        elif "approved" in properties:
            response = {
                "approved": True,
                "confidence": 0.94,
                "issues": [],
                "explanation": (
                    "The proposed patch addresses SQL injection."
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
                "suggested_remediation": (
                    "Use parameterized SQL queries."
                ),
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


def make_agent_input():
    finding = Finding(
        finding_id="repair-test-1",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        confidence=0.9,
        message="Potential SQL injection",
        explanation="User input is concatenated into SQL.",
        file_path="example.py",
        line_number=2,
        evidence=(
            'query = "SELECT * FROM users WHERE id = " + user_id'
        ),
        source="test",
        suggested_remediation="Use parameterized SQL queries.",
    )

    retrieval = RetrievalResponse(
        query="SQL injection prevention",
        chunks=[],
    )

    return AgentInput(
        finding=finding,
        retrieval=retrieval,
    )


def test_optional_repair_workflow_runs_all_four_agents(tmp_path):
    provider = RepairWorkflowFakeProvider()
    log_path = tmp_path / "repair_runs.jsonl"

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=log_path,
        generate_patch=True,
    )

    assert provider.call_count == 4

    assert result.detector_assessment.cwe_id == "CWE-89"
    assert result.guideline_check.compliant is True

    assert result.patch is not None
    assert result.patch.unified_diff is not None

    # Deterministic validation must succeed before Critic is invoked.
    assert result.patch_validation is not None
    assert result.patch_validation.valid is True
    assert result.patch_validation.applied is True
    assert result.patch_validation.python_syntax_valid is True

    assert result.critic_review is not None
    assert result.critic_review.approved is True

    # Final acceptance requires both checks to pass.
    assert result.patch_accepted is True
    assert result.output.patch is not None

    records = [
        json.loads(line)
        for line in log_path.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert len(records) == 4

    assert [r["prompt_version"] for r in records] == [
        "detector-v1",
        "guideline-checker-v1",
        "refactor-v2",
        "critic-v2",
    ]


def test_repair_workflow_skips_critic_when_refactor_makes_no_change(
    tmp_path,
):
    provider = RepairWorkflowFakeProvider(patch_mode="no_change")

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "no_change_runs.jsonl",
        generate_patch=True,
        max_repair_attempts=0,
    )

    # Detector, Guideline Checker and Refactor run.
    # The unchanged source produces no diff, so validation rejects it.
    # The Critic must therefore be skipped.
    assert provider.call_count == 3

    assert result.patch is not None
    assert result.patch.unified_diff is None

    assert result.patch_validation is not None
    assert result.patch_validation.valid is False

    assert result.critic_review is None
    assert result.patch_accepted is False
    assert result.output.patch is None