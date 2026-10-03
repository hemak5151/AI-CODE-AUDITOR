from shared.schemas import ContextPackage, RetrievalResponse, Finding, Severity, Patch
from rag.chunking.markdown import chunk_markdown
from rag.retrieval import InMemoryRetriever
from agent.models.contracts import AgentInput

def test_member1_to_member3_context_contract():
    c=ContextPackage(target_function="run", callers=["main"], callees=["eval"], imports=["os"], taint_path=["input -> run"], token_trimmed_context="def run(): ...")
    assert c.target_function=="run"

def test_member2_to_member3_retrieval_contract():
    chunks=chunk_markdown("# Guide\n\n## Dynamic code execution\nAvoid eval and exec.","guide.md")
    result=InMemoryRetriever(chunks).retrieve("avoid eval")
    assert result.chunks and result.chunks[0].source=="guide.md"

def test_member3_to_member4_patch_contract():
    f=Finding(finding_id="x",severity=Severity.HIGH,confidence=.9,message="m",explanation="e",file_path="a.py",line_number=1,source="agent")
    patch=Patch(finding_id=f.finding_id, unified_diff="--- a.py\n+++ a.py\n", description="demo")
    assert patch.finding_id==f.finding_id
