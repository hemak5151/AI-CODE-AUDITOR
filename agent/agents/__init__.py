from agent.models.provider import MockLLMProvider
from agent.models.contracts import LLMRequest, AgentInput, AgentOutput

def run_detector(agent_input: AgentInput) -> AgentOutput:
    provider=MockLLMProvider()
    provider.generate(LLMRequest(prompt="Detect and explain this finding.", context=agent_input.finding.explanation))
    return AgentOutput(finding=agent_input.finding)
