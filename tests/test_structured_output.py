import pytest
from pydantic import create_model

from agent.models.contracts import LLMRequest, LLMResponse
from agent.models.provider import LLMProvider
from agent.models.structured_output import (
    StructuredOutputError,
    generate_structured,
)


Result = create_model("StructuredResult", answer=(str, ...))


class SequenceProvider(LLMProvider):
    """Test provider that returns predetermined responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def generate(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        content = self.responses.pop(0)

        return LLMResponse(
            content=content,
            model="test-provider",
            tokens=1,
        )


def test_valid_json_is_returned_as_pydantic_model():
    provider = SequenceProvider(['{"answer": "hello"}'])

    result = generate_structured(
        provider,
        LLMRequest(prompt="Return an answer."),
        Result,
    )

    assert result.answer == "hello"
    assert len(provider.requests) == 1
    assert provider.requests[0].response_format == Result.model_json_schema()


def test_invalid_json_retries_and_recovers():
    provider = SequenceProvider([
        "not valid JSON",
        '{"answer": "hello"}',
    ])

    result = generate_structured(
        provider,
        LLMRequest(prompt="Return an answer."),
        Result,
    )

    assert result.answer == "hello"
    assert len(provider.requests) == 2


def test_invalid_json_raises_after_max_attempts():
    provider = SequenceProvider([
        "not valid JSON",
        "still not valid JSON",
    ])

    with pytest.raises(StructuredOutputError):
        generate_structured(
            provider,
            LLMRequest(prompt="Return an answer."),
            Result,
            max_attempts=2,
        )

    assert len(provider.requests) == 2