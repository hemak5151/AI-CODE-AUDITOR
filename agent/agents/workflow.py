from agent.models.contracts import AgentInput, AgentOutput
from agent.models.provider import MockLLMProvider, LLMRequest

def run_detector(agent_input: AgentInput) -> AgentOutput:
    MockLLMProvider().generate(LLMRequest(prompt="Detect and explain this finding.", context=agent_input.finding.explanation))
    return AgentOutput(finding=agent_input.finding)
