
import json
from pathlib import Path

from agent.agents.workflow import run_agent_workflow
from agent.models.contracts import LLMRequest, LLMResponse
from agent.models.provider import LLMProvider, OllamaProvider

from test_sandbox_workflow import SOURCE_CODE, make_agent_input


MODEL = "qwen2.5-coder:7b"
MAX_REPAIR_ATTEMPTS = 1


def parse_response(content: str) -> dict:
    """Extract a JSON object from the model response."""

    content = content.strip()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")

        if start == -1 or end <= start:
            raise ValueError(
                "Could not extract structured JSON from Qwen response."
            )

        return json.loads(content[start:end + 1])


class FaultInjectingQwenProvider(LLMProvider):
    """
    Wrap the real Qwen provider.

    Deliberately introduces a syntax error into the first Refactor
    response. The subsequent attempt is handled by real Qwen using
    the validator feedback from the workflow.
    """

    def __init__(self, model: str):
        self.inner = OllamaProvider(model=model)
        self.refactor_calls = 0
        self.fault_injected = False
        self.retry_feedback_seen = False

    def generate(self, request: LLMRequest) -> LLMResponse:
        response = self.inner.generate(request)

        data = parse_response(response.content)

        # Only intervene in Refactor's structured response.
        if not isinstance(data, dict) or "revised_source" not in data:
            return response

        self.refactor_calls += 1

        if self.refactor_calls == 1:
            original_source = data["revised_source"]

            data["revised_source"] = (
                original_source.rstrip()
                + "\n\n"
                + "def intentionally_broken(:\n"
            )

            self.fault_injected = True

            print(
                "\n[EXPERIMENT] Injected a syntax error "
                "into the first real-Qwen patch."
            )

            return response.model_copy(
                update={"content": json.dumps(data)}
            )

        if self.refactor_calls > 1:
            self.retry_feedback_seen = (
                "Validator error:" in request.prompt
            )

            print(
                "\n[EXPERIMENT] Real Qwen received "
                "validator feedback for its repair attempt."
            )

        return response


def main():
    experiment_dir = (
        Path(__file__).resolve().parents[1]
        / "logs"
        / "real_qwen_iterative"
    )

    experiment_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_log = experiment_dir / "agent_runs.jsonl"
    repair_log = experiment_dir / "repair_attempts.jsonl"
    summary_path = experiment_dir / "summary.json"

    provider = FaultInjectingQwenProvider(MODEL)

    print("=" * 65)
    print("REAL QWEN ITERATIVE REPAIR EXPERIMENT")
    print("=" * 65)

    print(f"Model: {MODEL}")
    print("Initial repair limit:", MAX_REPAIR_ATTEMPTS)
    print("Sandbox: Static patch and Python syntax validation")
    print("Failure injection: First Refactor response only")

    result = run_agent_workflow(
        agent_input=make_agent_input(),
        source_code=SOURCE_CODE,
        provider=provider,
        log_path=model_log,
        generate_patch=True,
        max_repair_attempts=MAX_REPAIR_ATTEMPTS,
    )
    print("\n========== FINAL GENERATED DIFF ==========")

    if result.patch is not None:
        print(result.patch.unified_diff or "<empty diff>")
    else:
        print("<no patch returned>")
    attempt_records = []

    if repair_log.exists():
        attempt_records = [
            json.loads(line)
            for line in repair_log.read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]

    validation = (
        result.patch_validation.model_dump()
        if result.patch_validation is not None
        else None
    )

    critic = (
        result.critic_review.model_dump()
        if result.critic_review is not None
        else None
    )

    summary = {
        "experiment": "controlled_real_qwen_iterative_repair",
        "model": MODEL,
        "fault_injection": (
            "A syntax error was deliberately appended to "
            "the first Qwen-generated revised source."
        ),
        "fault_injected": provider.fault_injected,
        "retry_feedback_received": provider.retry_feedback_seen,
        "refactor_calls": provider.refactor_calls,
        "repair_attempts": result.repair_attempts,
        "maximum_repair_attempts": MAX_REPAIR_ATTEMPTS,
        "patch_accepted": result.patch_accepted,
        "patch_validation": validation,
        "critic_review": critic,
        "attempt_records": attempt_records,
    }

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    print("\n========== EXPERIMENT RESULT ==========")

    print(json.dumps(summary, indent=2, default=str))

    success = (
        provider.fault_injected
        and provider.retry_feedback_seen
        and provider.refactor_calls == 2
        and result.repair_attempts == 1
        and result.patch_accepted
    )

    print("\n========== FINAL STATUS ==========")

    if success:
        print("EXPERIMENT PASSED")
        print("Real Qwen corrected the deliberately failed first attempt.")
    else:
        print("EXPERIMENT NEEDS REVIEW")
        print("Inspect the summary and execution logs.")

    print(f"\nEvidence saved to: {experiment_dir}")

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
