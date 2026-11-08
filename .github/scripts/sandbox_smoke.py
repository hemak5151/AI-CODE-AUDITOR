import os
import subprocess
import sys
import tempfile
from pathlib import Path

from agent.patches.sandbox import DockerSandboxRunner

IMAGE = "python:3.12-slim"
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))


def py(code):
    return ["python", "-c", code]


ws = Path(tempfile.mkdtemp())
os.chmod(ws, 0o755)  # the container runs as uid 65534 and must be able to read it
(ws / "hello.txt").write_text("hi")
os.chmod(ws / "hello.txt", 0o644)

res = DockerSandboxRunner(IMAGE, timeout_seconds=60).run(ws, py("print(open('/workspace/hello.txt').read())"))
check("normal command passes and sees the workspace", res.status == "passed" and "hi" in res.stdout, res.stderr[-200:])

res = DockerSandboxRunner(IMAGE, timeout_seconds=60).run(
    ws, py("import socket; socket.create_connection(('1.1.1.1', 80), timeout=3)"))
check("network is blocked", res.status == "failed" and "Errno" in res.stderr, res.stderr[-200:])

res = DockerSandboxRunner(IMAGE, timeout_seconds=60).run(ws, py("open('/workspace/x', 'w')"))
check("workspace is read-only", res.status == "failed" and "Errno" in res.stderr, res.stderr[-200:])

res = DockerSandboxRunner(IMAGE, memory_limit="64m", timeout_seconds=60).run(
    ws, py("x = b'a' * (300 * 1024 * 1024)"))
check("memory limit kills a memory hog", res.status == "failed", f"{res.status} {res.exit_code}")

res = DockerSandboxRunner(IMAGE, timeout_seconds=3).run(ws, py("import time; time.sleep(30)"))
check("timeout is enforced", res.status == "timeout", f"{res.status} {res.errors}")
check("timeout cleanup confirmed", not any("cleanup" in e.lower() for e in res.errors), str(res.errors))

left = subprocess.run(["docker", "ps", "-a", "-q", "--filter", "name=auditor-sandbox"],
                      capture_output=True, text=True).stdout.strip()
check("no container left behind", left == "", left)

sys.exit(0 if all(results) else 1)