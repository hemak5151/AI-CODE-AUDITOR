from analysis_engine import analyze_python

def test_extracts_structure_and_finds_eval():
    result=analyze_python('import os\n\nclass A:\n    def run(self, x):\n        return eval(x)\n')
    assert "A" in result.classes
    assert "run" in result.functions
    assert "os" in result.imports
    assert any(f.cwe_id == "CWE-95" for f in result.findings)

def test_parse_error():
    result=analyze_python('def broken(:\n')
    assert result.parse_error
