from datetime import date
from shared.schemas import RunLog

def new_run_log(model="mock-local", prompt_version="v0", seed=None, tokens=None, latency_ms=None, commit_hash=None):
    return RunLog(model=model,prompt_version=prompt_version,seed=seed,tokens=tokens,latency_ms=latency_ms,commit_hash=commit_hash,date=date.today().isoformat())
