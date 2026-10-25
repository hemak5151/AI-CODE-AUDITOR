import json

from agent.agents.workflow import run_agent_workflow
from agent.models.contracts import AgentInput, LLMRequest, LLMResponse
from agent.models.provider import LLMProvider
from shared.schemas.finding import Finding, Severity
from shared.schemas.interfaces import RetrievalChunk, RetrievalResponse


class FakeProvider(LLMProvider):
    """Return predictable responses without calling a real model."""

    def __init__(self):
        self.call_count = 0

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.call_count += 1
        schema = request.response_format or {}
        properties = schema.get("properties", {})

        if "compliant" in properties:
            content = {
                "compliant": True,
                "confidence": 0.95,
                "reason": (
                    "The proposed remediation matches the supplied "
                    "parameterized-query guidance."
                ),
                "guideline_reference": (
                    "test-security-guide.md#Parameterized-queries"
                ),
                "recommended_action": (
                    "Use parameterized SQL queries."
                ),
            }
        else:
            content = {
                "cwe_id": "CWE-89",
                "severity": "high",
                "confidence": 0.91,
                "message": "Potential SQL injection",
                "explanation": (
                    "User input is concatenated into an SQL query."
                ),
                "line_number": 2,
                "evidence": (
                    'query = "SELECT * FROM users WHERE id = " + user_id'
                ),
                "suggested_remediation": (
                    "Use a parameterized SQL query."
                ),
            }

        return LLMResponse(
            content=json.dumps(content),
            model="test-model",
            tokens=17,
        )


def make_agent_input() -> AgentInput:
    finding = Finding(
        finding_id="test-finding-1",
        cwe_id="CWE-89",
        severity=Severity.HIGH,
        confidence=0.8,
        message="Potential SQL injection",
        explanation="User input is concatenated into SQL.",
        file_path="example.py",
        line_number=2,
        evidence='query = "SELECT * FROM users WHERE id = " + user_id',
        source="test",
        suggested_remediation="Use a parameterized SQL query.",
    )

    retrieval = RetrievalResponse(
        query="SQL injection prevention",
        chunks=[
            RetrievalChunk(
                source="test-security-guide.md",
                section="Parameterized queries",
                score=0.95,
                content=(
                    "Use parameterized SQL queries to prevent "
                    "SQL injection."
                ),
            )
        ],
    )

    return AgentInput(
        finding=finding,
        retrieval=retrieval,
    )


def test_workflow_runs_detector_then_guideline_checker(tmp_path):
    provider = FakeProvider()
    log_path = tmp_path / "agent_runs.jsonl"

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=(
            'user_id = input("User ID: ")\n'
            'query = "SELECT * FROM users WHERE id = " + user_id'
        ),
        provider=provider,
        log_path=log_path,
    )

    assert provider.call_count == 2
    assert result.detector_assessment.cwe_id == "CWE-89"
    assert result.detector_assessment.line_number == 2
    assert result.guideline_check.compliant is True
    assert result.output.finding.cwe_id == "CWE-89"
    assert result.output.finding.line_number == 2


def test_workflow_logs_both_model_calls(tmp_path):
    provider = FakeProvider()
    log_path = tmp_path / "agent_runs.jsonl"

    run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=(
            'user_id = input("User ID: ")\n'
            'query = "SELECT * FROM users WHERE id = " + user_id'
        ),
        provider=provider,
        log_path=log_path,
    )

    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]

    assert len(records) == 2
    assert records[0]["prompt_version"] == "detector-v1"
    assert records[1]["prompt_version"] == "guideline-checker-v1"
    assert all(record["model"] == "test-model" for record in records)
    assert all(record["tokens"] == 17 for record in records)
    assert all(record["latency_ms"] >= 0 for record in records)
    assert all(record["date"] for record in records)