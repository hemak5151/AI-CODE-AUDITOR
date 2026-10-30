
import json
import logging
import os

from collections.abc import Sequence
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
from agent.agents.refactor import generate_patch
from agent.agents.critic import CriticResult, review_patch

from agent.models.contracts import (
    AgentInput,
    AgentOutput,
    LLMRequest,
    LLMResponse,
)
from agent.models.provider import LLMProvider, OllamaProvider

from agent.patches.validator import (
    PatchValidationResult,
    validate_unified_diff,
)
from agent.patches.sandbox import DockerSandboxRunner
from agent.patches.staging import (
    StagingResult,
    validate_and_run_patch,
)

from shared.schemas.finding import Finding, LineRange
from shared.schemas.interfaces import Patch, RunLog


LOGGER = logging.getLogger(__name__)

DEFAULT_MODEL = os.getenv(
    "AI_CODE_AUDITOR_MODEL",
    "qwen2.5-coder:7b",
)

PROMPT_VERSIONS = {
    "detector": "detector-v1",
    "guideline_checker": "guideline-checker-v1",
    "refactor": "refactor-v2",
    "critic": "critic-v2",
}


class WorkflowState(TypedDict, total=False):
    agent_input: AgentInput
    source_code: str
    generate_patch: bool
    detector_result: DetectorResult
    updated_finding: Finding
    guideline_result: GuidelineCheckResult
    patch: Patch
    patch_validation: PatchValidationResult
    staging_result: StagingResult
    critic_result: CriticResult


class WorkflowResult(BaseModel):
    output: AgentOutput
    detector_assessment: DetectorResult
    guideline_check: GuidelineCheckResult
    patch: Patch | None = None
    patch_validation: PatchValidationResult | None = None
    staging_result: StagingResult | None = None
    critic_review: CriticResult | None = None
    patch_accepted: bool = False


class LoggingLLMProvider(LLMProvider):
    """Record model identity, prompt version, tokens and latency."""

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

            with self.log_path.open(
                "a",
                encoding="utf-8",
            ) as log_file:
                log_file.write(
                    json.dumps(
                        record.model_dump(),
                        ensure_ascii=False,
                    ) + "\n"
                )

        except OSError:
            LOGGER.exception("Unable to write model-run log")

        return response


def _resolve_source_code(
    agent_input: AgentInput,
    source_code: str | None,
) -> str:
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
    sandbox_runner: DockerSandboxRunner | None = None,
    sandbox_command: Sequence[str] | None = None,
):
    """Build the agent workflow with optional sandbox execution."""

    if (sandbox_runner is None) != (sandbox_command is None):
        raise ValueError(
            "Provide both sandbox_runner and sandbox_command, "
            "or neither."
        )

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

        logged_provider = LoggingLLMProvider(
            provider,
            PROMPT_VERSIONS["detector"],
            log_path,
        )

        assessment = detect_snippet(
            provider=logged_provider,
            code=state["source_code"],
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

    def refactor_node(state: WorkflowState) -> dict:
        agent_input = state["agent_input"]

        logged_provider = LoggingLLMProvider(
            provider,
            PROMPT_VERSIONS["refactor"],
            log_path,
        )

        patch = generate_patch(
            provider=logged_provider,
            finding=state["updated_finding"],
            source_code=state["source_code"],
            context=agent_input.context,
            retrieval=agent_input.retrieval,
        )

        return {"patch": patch}

    def validator_node(state: WorkflowState) -> dict:
        patch = state["patch"]
        agent_input = state["agent_input"]

        if sandbox_runner is not None:
            # Validate the patch, create disposable staging,
            # and execute only through the supplied sandbox runner.
            staging = validate_and_run_patch(
                original_source=state["source_code"],
                diff_text=patch.unified_diff or "",
                expected_file_path=agent_input.finding.file_path,
                runner=sandbox_runner,
                command=sandbox_command,
            )

            return {
                "patch_validation": staging.validation,
                "staging_result": staging,
            }

        # Static-only mode for local development without Docker.
        validation = validate_unified_diff(
            original_source=state["source_code"],
            diff_text=patch.unified_diff or "",
            expected_file_path=agent_input.finding.file_path,
        )

        return {"patch_validation": validation}

    def critic_node(state: WorkflowState) -> dict:
        agent_input = state["agent_input"]

        logged_provider = LoggingLLMProvider(
            provider,
            PROMPT_VERSIONS["critic"],
            log_path,
        )

        result = review_patch(
            provider=logged_provider,
            finding=state["updated_finding"],
            patch=state["patch"],
            source_code=state["source_code"],
            context=agent_input.context,
            retrieval=agent_input.retrieval,
        )

        return {"critic_result": result}

    def route_after_guidelines(state: WorkflowState) -> str:
        return (
            "refactor"
            if state.get("generate_patch", False)
            else "end"
        )

    def route_after_validation(state: WorkflowState) -> str:
        validation = state.get("patch_validation")

        if validation is None or not validation.valid:
            return "end"

        if sandbox_runner is not None:
            staging = state.get("staging_result")

            if staging is None or not staging.accepted:
                return "end"

        return "critic"

    graph = StateGraph(WorkflowState)

    graph.add_node("detector", detector_node)
    graph.add_node("guideline_checker", guideline_node)
    graph.add_node("refactor", refactor_node)
    graph.add_node("patch_validator", validator_node)
    graph.add_node("critic", critic_node)

    graph.add_edge(START, "detector")
    graph.add_edge("detector", "guideline_checker")

    graph.add_conditional_edges(
        "guideline_checker",
        route_after_guidelines,
        {
            "refactor": "refactor",
            "end": END,
        },
    )

    graph.add_edge("refactor", "patch_validator")

    graph.add_conditional_edges(
        "patch_validator",
        route_after_validation,
        {
            "critic": "critic",
            "end": END,
        },
    )

    graph.add_edge("critic", END)

    return graph.compile()


def run_agent_workflow(
    agent_input: AgentInput,
    source_code: str | None = None,
    provider: LLMProvider | None = None,
    log_path: Path | None = None,
    generate_patch: bool = False,
    sandbox_runner: DockerSandboxRunner | None = None,
    sandbox_command: Sequence[str] | None = None,
) -> WorkflowResult:
    """Run the agents with optional dynamic sandbox validation."""

    if (sandbox_runner is None) != (sandbox_command is None):
        raise ValueError(
            "Provide both sandbox_runner and sandbox_command, "
            "or neither."
        )

    code = _resolve_source_code(agent_input, source_code)

    graph = build_agent_graph(
        provider=provider,
        log_path=log_path,
        sandbox_runner=sandbox_runner,
        sandbox_command=sandbox_command,
    )

    state = graph.invoke({
        "agent_input": agent_input,
        "source_code": code,
        "generate_patch": generate_patch,
    })

    validation = state.get("patch_validation")
    staging = state.get("staging_result")
    critic_review = state.get("critic_result")
    proposed_patch = state.get("patch")

    sandbox_passed = (
        sandbox_runner is None
        or (
            staging is not None
            and staging.accepted
            and staging.execution is not None
            and staging.execution.status == "passed"
        )
    )

    accepted = bool(
        validation is not None
        and validation.valid
        and sandbox_passed
        and critic_review is not None
        and critic_review.approved
    )

    return WorkflowResult(
        output=AgentOutput(
            finding=state["updated_finding"],
            patch=proposed_patch if accepted else None,
        ),
        detector_assessment=state["detector_result"],
        guideline_check=state["guideline_result"],
        patch=proposed_patch,
        patch_validation=validation,
        staging_result=staging,
        critic_review=critic_review,
        patch_accepted=accepted,
    )


def run_detector(agent_input: AgentInput) -> AgentOutput:
    """Compatibility wrapper for existing callers."""

    return run_agent_workflow(agent_input).output
