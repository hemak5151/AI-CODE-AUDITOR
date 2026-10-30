
from agent.agents.workflow import run_agent_workflow
from agent.models.contracts import AgentInput
from agent.models.provider import OllamaProvider
from shared.schemas.finding import Finding, Severity
from shared.schemas.interfaces import RetrievalResponse


def main():
    # Complete vulnerable SQLite example.
    # Providing the database driver makes the required
    # parameter-placeholder syntax unambiguous.

    code = '''import sqlite3

def fetch_user(user_id):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    result = cursor.fetchone()
    connection.close()
    return result
'''

    finding = Finding(
        finding_id="real-demo-sqli-002",
        cwe_id=None,
        severity=Severity.HIGH,
        confidence=0.80,
        message="Potential SQL injection",
        explanation=(
            "User input is concatenated directly into an SQL query."
        ),
        file_path="submitted.py",
        line_number=6,
        evidence=(
            'query = "SELECT * FROM users WHERE id = " + user_id'
        ),
        source="manual-demo",
        suggested_remediation=(
            "Use a parameterized SQLite query."
        ),
    )

    # Actual Member 2 RAG results will be integrated later.
    retrieval = RetrievalResponse(
        query="SQLite SQL injection prevention",
        chunks=[],
    )

    agent_input = AgentInput(
        finding=finding,
        retrieval=retrieval,
    )

    provider = OllamaProvider(
        model="qwen2.5-coder:7b"
    )

    print("\nStarting four-agent workflow...\n")

    result = run_agent_workflow(
        agent_input=agent_input,
        source_code=code,
        provider=provider,
        generate_patch=True,
    )

    print("\n========== DETECTOR RESULT ==========")
    print(result.detector_assessment.model_dump_json(indent=2))

    print("\n========== GUIDELINE CHECK ==========")
    print(result.guideline_check.model_dump_json(indent=2))

    print("\n========== GENERATED PATCH ==========")
    if result.patch is not None:
        print(result.patch.model_dump_json(indent=2))
    else:
        print("No patch was generated.")

    print("\n========== CRITIC REVIEW ==========")
    if result.critic_review is not None:
        print(result.critic_review.model_dump_json(indent=2))
    else:
        print("Critic was not invoked.")

    print("\n========== FINAL RESULT ==========")
    print(result.model_dump_json(indent=2))

    print("\nCheck logs/agent_runs.jsonl for execution records.")


if __name__ == "__main__":
    main()
