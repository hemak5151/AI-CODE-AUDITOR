import csv
from pathlib import Path
from time import perf_counter

import ollama

from agent.models.contracts import LLMRequest
from agent.models.provider import OllamaProvider


MODELS = [
    "qwen2.5-coder:7b",
    "qwen2.5-coder:0.5b",
]

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "member3_week2_benchmark_runs.csv"
)

DETECTION_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerability": {"type": "boolean"},
        "cwe_id": {
            "type": "string",
            "enum": ["CWE-89", "none"],
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical"],
        },
        "line_number": {"type": "integer"},
        "rationale": {"type": "string"},
    },
    "required": [
        "vulnerability",
        "cwe_id",
        "severity",
        "line_number",
        "rationale",
    ],
    "additionalProperties": False,
}

PROMPTS = [
    (
        "sql_concept",
        (
            "In no more than 25 words, explain why parameterized SQL "
            "queries are safer than string concatenation."
        ),
        None,
    ),
    (
        "sql_injection_detection",
        (
            "Analyze this Python code for potential SQL injection. "
            "Distinguish a potential vulnerability from proof of "
            "exploitability. Return CWE-89 if applicable, otherwise "
            "use cwe_id 'none'.\n\n"
            "Source code:\n"
            '1: user_id = input("User ID: ")\n'
            '2: query = "SELECT * FROM users WHERE id = " + user_id\n'
        ),
        DETECTION_SCHEMA,
    ),
    (
        "parameterized_fix",
        (
            "Rewrite this code to use a parameterized SQLite query. "
            "Assume cursor exists. Return only the replacement Python code.\n\n"
            'user_id = input("User ID: ")\n'
            'query = "SELECT * FROM users WHERE id = " + user_id\n'
            "cursor.execute(query)\n"
        ),
        None,
    ),
]


def get_field(item, name, default=None):
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def get_loaded_model_size(model_name):
    try:
        info = ollama.ps()
        loaded_models = get_field(info, "models", []) or []

        for item in loaded_models:
            name = get_field(item, "name", "")
            model = get_field(item, "model", "")

            if name == model_name or model == model_name:
                size = get_field(item, "size")
                if size is not None:
                    return f"{size / (1024 ** 3):.2f} GiB"

        return "not reported"

    except Exception as exc:
        return f"unavailable: {exc}"


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # Never silently overwrite an earlier benchmark run.
    try:
        result_file = OUTPUT.open(
            "x",
            newline="",
            encoding="utf-8",
        )
    except FileExistsError:
        raise SystemExit(
            f"Results file already exists: {OUTPUT}\n"
            "It was not overwritten. Keep the earlier results "
            "and choose a new filename before rerunning."
        )

    fields = [
        "model",
        "case",
        "repeat",
        "latency_seconds",
        "tokens",
        "ollama_reported_model_size",
        "response",
        "error",
    ]

    with result_file:
        writer = csv.DictWriter(result_file, fieldnames=fields)
        writer.writeheader()
        result_file.flush()

        for model_name in MODELS:
            print(f"\n=== Model: {model_name} ===")
            provider = OllamaProvider(model=model_name)

            # Record initial loading / first-call latency separately.
            started = perf_counter()
            try:
                warmup_response = provider.generate(
                    LLMRequest(prompt="Reply with exactly: ready")
                )
                cold_seconds = perf_counter() - started
                size = get_loaded_model_size(model_name)

                writer.writerow({
                    "model": model_name,
                    "case": "initial_load_and_warmup",
                    "repeat": 1,
                    "latency_seconds": round(cold_seconds, 3),
                    "tokens": warmup_response.tokens,
                    "ollama_reported_model_size": size,
                    "response": warmup_response.content,
                    "error": "",
                })
                result_file.flush()

                print(f"Initial call: {cold_seconds:.2f} seconds")
                print(f"Ollama-reported model size: {size}")

            except Exception as exc:
                writer.writerow({
                    "model": model_name,
                    "case": "initial_load_and_warmup",
                    "repeat": 1,
                    "latency_seconds": "",
                    "tokens": "",
                    "ollama_reported_model_size": "",
                    "response": "",
                    "error": str(exc),
                })
                result_file.flush()
                print(f"Model failed to initialize: {exc}")
                continue

            # Two measured runs per task, after the initial model load.
            for case, prompt, response_format in PROMPTS:
                for repeat in range(1, 3):
                    request = LLMRequest(
                        prompt=prompt,
                        response_format=response_format,
                    )

                    started = perf_counter()

                    try:
                        response = provider.generate(request)
                        elapsed = perf_counter() - started

                        writer.writerow({
                            "model": model_name,
                            "case": case,
                            "repeat": repeat,
                            "latency_seconds": round(elapsed, 3),
                            "tokens": response.tokens,
                            "ollama_reported_model_size": size,
                            "response": response.content,
                            "error": "",
                        })
                        result_file.flush()

                        print(
                            f"{case}, run {repeat}: "
                            f"{elapsed:.2f}s, "
                            f"{response.tokens} tokens"
                        )
                        print(f"Response: {response.content[:350]}")

                    except Exception as exc:
                        writer.writerow({
                            "model": model_name,
                            "case": case,
                            "repeat": repeat,
                            "latency_seconds": "",
                            "tokens": "",
                            "ollama_reported_model_size": size,
                            "response": "",
                            "error": str(exc),
                        })
                        result_file.flush()
                        print(f"{case}, run {repeat} failed: {exc}")

    print(f"\nBenchmark results saved to:\n{OUTPUT}")


if __name__ == "__main__":
    main()