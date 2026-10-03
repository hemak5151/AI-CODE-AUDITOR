# Python Security Guidelines

## Dynamic code execution
Avoid eval and exec on untrusted input. Prefer explicit parsing and allow-listed operations.

## Command execution
Avoid shell=True with untrusted command data. Prefer subprocess argument lists and shell=False.

## Secrets
Do not hardcode passwords, API keys, tokens, or other credentials in source code. Use environment variables or a secret manager.
