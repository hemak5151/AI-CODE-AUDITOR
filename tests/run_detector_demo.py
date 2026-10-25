from agent.agents.detector import detect_snippet
from agent.models.provider import OllamaProvider

code = '''user_id = input("User ID: ")
query = "SELECT * FROM users WHERE id = " + user_id
'''

result = detect_snippet(
    provider=OllamaProvider(model="qwen2.5-coder:7b"),
    code=code,
    file_path="submitted.py",
)

print(result.model_dump_json(indent=2))