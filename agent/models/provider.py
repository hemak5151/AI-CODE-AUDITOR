from .contracts import LLMRequest, LLMResponse

class LLMProvider:
    def generate(self, request: LLMRequest) -> LLMResponse:
        raise NotImplementedError

class MockLLMProvider(LLMProvider):
    def generate(self, request: LLMRequest) -> LLMResponse:
        return LLMResponse(content="Mock reasoning response. Replace this provider with Ollama/Qwen2.5-Coder later.")
