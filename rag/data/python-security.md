# Python Security Guidelines

## Dynamic code execution
Avoid eval and exec on untrusted input. Prefer explicit parsing and allow-listed operations.


## Command execution

Avoid shell=True when executing subprocess commands with untrusted command data. Prefer subprocess argument lists and shell=False to launch system processes securely.

Do not build shell commands directly from user input. Use safe command arguments to reduce command injection risks when running external programs or operating system processes.



## Secrets

Do not hardcode passwords, API keys, tokens, or other credentials in source code. Avoid storing passwords in Python files or exposing credentials in application code. Do not commit access tokens or private API keys to version control.

Use environment variables or a secret manager to store application secrets securely. Keep database passwords, authentication credentials, and service tokens outside source files.


## SQL Injection

SQL injection happens when an application directly combines user input with SQL queries. Attackers may manipulate the query to access, modify, or delete database information.

Avoid building SQL queries using string concatenation or formatting with untrusted input. Use parameterized queries or prepared statements instead.

## Path Traversal

Path traversal happens when an application allows user input to control file paths without proper validation. Attackers may use values such as ../ to access files outside the intended directory.

Validate user-supplied file paths. Restrict file access to an allowed directory and verify that the resolved path stays within that directory.

## Insecure File Handling

Insecure file handling happens when applications accept or process files without sufficient validation. This can expose applications to malicious uploads, unauthorized file access, or unsafe file operations.

Validate uploaded file types, restrict file sizes, generate safe filenames, and avoid trusting user-supplied file paths. Store uploads outside publicly accessible directories when appropriate.

## Unsafe Deserialization

Unsafe deserialization happens when an application loads untrusted serialized data without checking its safety. In Python, using pickle to load untrusted data can allow attackers to execute arbitrary code.

Never use pickle.load() or pickle.loads() on untrusted data. Prefer safer data formats such as JSON when possible, and validate the data before using it.
