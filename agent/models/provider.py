import ollama

from .contracts import LLMRequest, LLMResponse


class LLMProvider:
    def generate(self, request: LLMRequest) -> LLMResponse:
        raise NotImplementedError


class MockLLMProvider(LLMProvider):
    def generate(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(
            content="Mock reasoning response. Replace this provider with Ollama/Qwen2.5-Coder later."
        )


class OllamaProvider(LLMProvider):
    def __init__(self, model: str = "qwen2.5-coder:7b"):
        self.model = model

    def generate(self, request: LLMRequest) -> LLMResponse:
        prompt = request.prompt

        if request.context:
            prompt = f"{prompt}\n\nContext:\n{request.context}"

        chat_options = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        if request.response_format is not None:
            chat_options["format"] = request.response_format

        response = ollama.chat(**chat_options)

        content = response["message"]["content"]
        tokens = response.get("eval_count", 0) or 0

        return LLMResponse(
            content=content,
            model=self.model,
            tokens=tokens,
        )