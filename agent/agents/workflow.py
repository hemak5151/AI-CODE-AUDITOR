import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel

from agent.agents.detector import DetectorResult, detect_snippet
from agent.agents.guideline_checker import (
    GuidelineCheckResult,
    check_guideline_compliance,
)
from agent.models.contracts import (
    AgentInput,
    AgentOutput,
    LLMRequest,
    LLMResponse,
)
from agent.models.provider import LLMProvider, OllamaProvider
from shared.schemas.finding import Finding, LineRange
from shared.schemas.interfaces import RunLog


LOGGER = logging.getLogger(__name__)
DEFAULT_MODEL = os.getenv(
    "AI_CODE_AUDITOR_MODEL",
    "qwen2.5-coder:7b",
)
PROMPT_VERSIONS = {
    "detector": "detector-v1",
    "guideline_checker": "guideline-checker-v1",
}


class WorkflowState(TypedDict, total=False):
    agent_input: AgentInput
    source_code: str
    detector_result: DetectorResult
    updated_finding: Finding
    guideline_result: GuidelineCheckResult


class WorkflowResult(BaseModel):
    output: AgentOutput
    detector_assessment: DetectorResult
    guideline_check: GuidelineCheckResult


class LoggingLLMProvider(LLMProvider):
    """Wrap a provider and record each successful model call."""

    def __init__(
        self,
        provider: LLMProvider,
        prompt_version: str,
        log_path: Path,
    ):
        self.provider = provider
        self.prompt_version = prompt_version
        self.log_path = log_path

    def generate(self, request: LLMRequest) -> LLMResponse:
        started = perf_counter()

        try:
            response = self.provider.generate(request)
        except Exception:
            LOGGER.exception(
                "Model call failed; prompt_version=%s",
                self.prompt_version,
            )
            raise

        latency_ms = (perf_counter() - started) * 1000

        record = RunLog(
            model=response.model,
            prompt_version=self.prompt_version,
            tokens=response.tokens,
            latency_ms=round(latency_ms, 2),
            commit_hash=None,
            date=datetime.now(timezone.utc).isoformat(),
        )

        try:
            self.log_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            with self.log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(
                    json.dumps(record.model_dump(), ensure_ascii=False)
                    + "\n"
                )
        except OSError:
            LOGGER.exception("Unable to write model-run log")

        return response


def _resolve_source_code(
    agent_input: AgentInput,
    source_code: str | None,
) -> str:
    """Prefer full supplied code, then repository context, then evidence."""

    candidates = [
        source_code,
        (
            agent_input.context.token_trimmed_context
            if agent_input.context is not None
            else None
        ),
        agent_input.finding.evidence,
    ]

    for candidate in candidates:
        if candidate and candidate.strip():
            return candidate

    raise ValueError(
        "No source code is available. Supply source_code, "
        "ContextPackage.token_trimmed_context, or finding.evidence."
    )


def _update_finding(
    original: Finding,
    assessment: DetectorResult,
) -> Finding:
    """Apply the detector assessment without changing the Finding contract."""

    updates = {
        "severity": assessment.severity,
        "confidence": assessment.confidence,
        "message": assessment.message,
        "explanation": assessment.explanation,
        "line_number": assessment.line_number,
        "evidence": assessment.evidence or original.evidence,
        "suggested_remediation": (
            assessment.suggested_remediation
            or original.suggested_remediation
        ),
    }

    # Preserve an existing CWE classification if the detector is uncertain.
    if assessment.cwe_id is not None:
        updates["cwe_id"] = assessment.cwe_id

    if original.line_range is not None:
        updates["line_range"] = LineRange(
            start=assessment.line_number,
            end=assessment.line_number,
        )

    return original.model_copy(update=updates)


def build_agent_graph(
    provider: LLMProvider | None = None,
    log_path: Path | None = None,
):
    """Build a Detector -> Guideline Checker LangGraph workflow."""

    if provider is None:
        provider = OllamaProvider(model=DEFAULT_MODEL)

    if log_path is None:
        log_path = (
            Path(__file__).resolve().parents[2]
            / "logs"
            / "agent_runs.jsonl"
        )

    def detector_node(state: WorkflowState) -> dict:
        agent_input = state["agent_input"]
        code = state["source_code"]

        logged_provider = LoggingLLMProvider(
            provider,
            PROMPT_VERSIONS["detector"],
            log_path,
        )

        assessment = detect_snippet(
            provider=logged_provider,
            code=code,
            file_path=agent_input.finding.file_path,
        )

        updated_finding = _update_finding(
            agent_input.finding,
            assessment,
        )

        return {
            "detector_result": assessment,
            "updated_finding": updated_finding,
        }

    def guideline_node(state: WorkflowState) -> dict:
        original_input = state["agent_input"]

        updated_input = AgentInput(
            finding=state["updated_finding"],
            context=original_input.context,
            retrieval=original_input.retrieval,
        )

        logged_provider = LoggingLLMProvider(
            provider,
            PROMPT_VERSIONS["guideline_checker"],
            log_path,
        )

        result = check_guideline_compliance(
            provider=logged_provider,
            agent_input=updated_input,
            detector_assessment=state["detector_result"],
        )

        return {"guideline_result": result}

    graph = StateGraph(WorkflowState)
    graph.add_node("detector", detector_node)
    graph.add_node("guideline_checker", guideline_node)
    graph.add_edge(START, "detector")
    graph.add_edge("detector", "guideline_checker")
    graph.add_edge("guideline_checker", END)

    return graph.compile()


def run_agent_workflow(
    agent_input: AgentInput,
    source_code: str | None = None,
    provider: LLMProvider | None = None,
    log_path: Path | None = None,
) -> WorkflowResult:
    """Run both agents and return their assessments and updated finding."""

    code = _resolve_source_code(agent_input, source_code)

    graph = build_agent_graph(
        provider=provider,
        log_path=log_path,
    )

    state = graph.invoke({
        "agent_input": agent_input,
        "source_code": code,
    })

    return WorkflowResult(
        output=AgentOutput(finding=state["updated_finding"]),
        detector_assessment=state["detector_result"],
        guideline_check=state["guideline_result"],
    )


def run_detector(agent_input: AgentInput) -> AgentOutput:
    """Compatibility wrapper for existing callers of run_detector."""

    return run_agent_workflow(agent_input).output