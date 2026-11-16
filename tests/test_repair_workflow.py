import json
import time
from pathlib import Path

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

class RejectCriticOnceProvider(RepairWorkflowFakeProvider):
    """Reject the first patch, then approve the repaired patch."""

    def __init__(self):
        super().__init__(patch_mode="valid")
        self.critic_calls = 0
        self.refactor_prompts = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        properties = (
            request.response_format or {}
        ).get("properties", {})

        if "revised_source" in properties:
            self.refactor_prompts.append(request.prompt)

        if "approved" in properties:
            self.critic_calls += 1

            if self.critic_calls == 1:
                self.call_count += 1
                response = {
                    "approved": False,
                    "confidence": 0.95,
                    "issues": [
                        "The first patch needs another review."
                    ],
                    "explanation": (
                        "First patch is insufficient; "
                        "replace SQL concatenation with a "
                        "parameterized query."
                    ),
                    "recommended_changes": (
                        "Use a parameterized SQL query."
                    ),
                }

                return LLMResponse(
                    content=json.dumps(response),
                    model="test-model",
                    tokens=25,
                )

        return super().generate(request)


def test_critic_rejection_triggers_bounded_repair_retry(tmp_path):
    provider = RejectCriticOnceProvider()

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "repair_retry.jsonl",
        generate_patch=True,
        max_repair_attempts=1,
    )

    # Initial workflow: Detector, Guideline Checker,
    # Refactor, Critic. Retry: Refactor, Critic.
    assert provider.call_count == 6
    assert provider.critic_calls == 2

    # Exactly one additional repair attempt occurred.
    assert result.repair_attempts == 1
    assert result.max_repair_attempts == 1

    # Refactor was called twice.
    assert len(provider.refactor_prompts) == 2

    # Critic feedback reached the second Refactor call.
    assert (
        "First patch is insufficient"
        in provider.refactor_prompts[1]
    )

    # The second patch was approved.
    assert result.critic_review is not None
    assert result.critic_review.approved is True
    assert result.patch_accepted is True
    assert result.output.patch is not None

class ValidationFailOnceProvider(RepairWorkflowFakeProvider):
    """Return invalid Python first, then a valid security fix."""

    def __init__(self):
        super().__init__(patch_mode="valid")
        self.refactor_calls = 0
        self.refactor_prompts = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        properties = (
            request.response_format or {}
        ).get("properties", {})

        if "revised_source" in properties:
            self.refactor_calls += 1
            self.refactor_prompts.append(request.prompt)

            if self.refactor_calls == 1:
                self.call_count += 1
                return LLMResponse(
                    content=json.dumps({
                        "revised_source": "def broken(:\n    pass\n",
                        "description": "Intentionally invalid Python for testing.",
                    }),
                    model="test-model",
                    tokens=25,
                )

        return super().generate(request)


def test_validation_failure_triggers_bounded_repair_retry(tmp_path):
    provider = ValidationFailOnceProvider()

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "validation_retry.jsonl",
        generate_patch=True,
        max_repair_attempts=1,
    )

    # Detector, Guideline Checker, two Refactor calls, one Critic call.
    assert provider.call_count == 5
    assert provider.refactor_calls == 2

    # Exactly one additional repair attempt occurred.
    assert result.repair_attempts == 1
    assert result.max_repair_attempts == 1

    # The second Refactor call received repair instructions.
    assert "This is a repair attempt." in provider.refactor_prompts[1]

    # The corrected patch passed validation and Critic review.
    assert result.critic_review is not None
    assert result.critic_review.approved is True
    assert result.patch_accepted is True
    assert result.output.patch is not None
    assert result.output.patch.unified_diff is not None

class RejectCriticNTimesProvider(RepairWorkflowFakeProvider):
    """Reject a fixed number of patches before approving one."""

    def __init__(self, rejection_count):
        super().__init__(patch_mode="valid")
        self.rejection_count = rejection_count
        self.critic_calls = 0
        self.refactor_calls = 0

    def generate(self, request: LLMRequest) -> LLMResponse:
        properties = (
            request.response_format or {}
        ).get("properties", {})

        if "revised_source" in properties:
            self.refactor_calls += 1

        if "approved" in properties:
            self.critic_calls += 1

            if self.critic_calls <= self.rejection_count:
                self.call_count += 1
                return LLMResponse(
                    content=json.dumps({
                        "approved": False,
                        "confidence": 0.95,
                        "issues": ["Additional correction required."],
                        "explanation": (
                            "The previous patch needs further correction."
                        ),
                        "recommended_changes": (
                            "Review and improve the parameterized SQL fix."
                        ),
                    }),
                    model="test-model",
                    tokens=25,
                )

        return super().generate(request)


def test_repair_depth_comparison(tmp_path):
    results = []

    # Three rejections require three additional repair attempts.
    for depth in range(4):
        provider = RejectCriticNTimesProvider(
            rejection_count=3
        )

        started = time.perf_counter()

        result = run_agent_workflow(
            agent_input=make_agent_input(),
            source_code=SOURCE_CODE,
            provider=provider,
            log_path=tmp_path / f"depth_{depth}.jsonl",
            generate_patch=True,
            max_repair_attempts=depth,
        )

        latency_ms = (time.perf_counter() - started) * 1000

        expected_acceptance = depth == 3

        assert result.repair_attempts == depth
        assert result.patch_accepted is expected_acceptance
        assert provider.refactor_calls == depth + 1
        assert provider.critic_calls == depth + 1

        results.append({
            "repair_depth": depth,
            "actual_repair_attempts": result.repair_attempts,
            "refactor_calls": provider.refactor_calls,
            "critic_calls": provider.critic_calls,
            "patch_accepted": result.patch_accepted,
            "latency_ms": round(latency_ms, 3),
            "model": "deterministic-fake-provider",
        })

    results_path = Path("research_results")
    results_path.mkdir(exist_ok=True)

    output_file = results_path / "member3_repair_depth_results.json"
    output_file.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print("\nREPAIR DEPTH EXPERIMENT")
    print(json.dumps(results, indent=2))
    print(f"\nResults saved to: {output_file}")
class CriticEffectivenessProvider(RepairWorkflowFakeProvider):
    """Produces a changed but still vulnerable patch."""

    def __init__(self):
        super().__init__(patch_mode="valid")
        self.critic_calls = 0

    def generate(self, request: LLMRequest) -> LLMResponse:
        properties = (
            request.response_format or {}
        ).get("properties", {})

        if "revised_source" in properties:
            self.call_count += 1
            return LLMResponse(
                content=json.dumps({
                    "revised_source": (
                        SOURCE_CODE
                        + "\n# SQL concatenation remains unsafe\n"
                    ),
                    "description": "Added a comment without fixing SQL injection.",
                }),
                model="test-model",
                tokens=25,
            )

        if "approved" in properties:
            self.critic_calls += 1
            self.call_count += 1
            return LLMResponse(
                content=json.dumps({
                    "approved": False,
                    "confidence": 0.99,
                    "issues": ["SQL injection remains unresolved."],
                    "explanation": (
                        "The patch does not replace SQL concatenation "
                        "with parameterized queries."
                    ),
                    "recommended_changes": (
                        "Use parameterized SQL queries."
                    ),
                }),
                model="test-model",
                tokens=25,
            )

        return super().generate(request)


def test_critic_rejects_patch_that_does_not_fix_vulnerability(tmp_path):
    provider = CriticEffectivenessProvider()

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "critic_effectiveness.jsonl",
        generate_patch=True,
        max_repair_attempts=0,
    )

    assert result.critic_review is not None
    assert result.critic_review.approved is False
    assert result.patch_accepted is False
    assert provider.critic_calls == 1
    assert "SQL injection remains unresolved." in result.critic_review.issues
def test_repair_stops_when_maximum_attempts_are_exhausted(tmp_path):
    provider = RejectCriticNTimesProvider(rejection_count=10)

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=tmp_path / "repair_exhausted.jsonl",
        generate_patch=True,
        max_repair_attempts=2,
    )

    assert result.repair_attempts == 2
    assert result.max_repair_attempts == 2
    assert provider.refactor_calls == 3
    assert provider.critic_calls == 3
    assert result.patch_accepted is False
    assert result.output.patch is None
    repair_log = tmp_path / "repair_attempts.jsonl"

    records = [
        json.loads(line)
        for line in repair_log.read_text(
            encoding="utf-8"
        ).splitlines()
    ]

    assert len(records) == 3
    assert [record["outcome"] for record in records] == [
    "critic_rejected",
    "critic_rejected",
    "critic_rejected",
    ]
    assert all(
        record["prompt_version"] == "repair-loop-v1"
        for record in records
    )
    assert all(record["date"] for record in records)
    assert all(record["details"] for record in records)

