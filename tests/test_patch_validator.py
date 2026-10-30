
from agent.patches.diff import unified_diff
from agent.patches.validator import validate_unified_diff


ORIGINAL_CODE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id = " + user_id\n'
    "    return query\n"
)

SAFE_CODE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id = ?"\n'
    "    return query\n"
)


def test_valid_patch_applies_and_python_parses():
    diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="example.py",
    )

    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
    )

    assert result.valid is True
    assert result.applied is True
    assert result.python_syntax_valid is True
    assert result.updated_source == SAFE_CODE


def test_validator_accepts_standard_git_path_prefixes():
    diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="example.py",
    )

    diff = diff.replace(
        "--- example.py\n",
        "--- a/example.py\n",
    ).replace(
        "+++ example.py\n",
        "+++ b/example.py\n",
    )

    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
    )

    assert result.valid is True
    assert result.updated_source == SAFE_CODE


def test_empty_patch_is_rejected():
    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text="",
        expected_file_path="example.py",
    )

    assert result.valid is False
    assert "Unified diff is empty." in result.errors


def test_missing_diff_headers_are_rejected():
    malformed_diff = (
        "@@ -1,1 +1,1 @@\n"
        "-old\n"
        "+new\n"
    )

    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text=malformed_diff,
        expected_file_path="example.py",
    )

    assert result.valid is False
    assert any(
        "header" in error.lower()
        for error in result.errors
    )


def test_mismatched_file_path_is_rejected():
    diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="different.py",
    )

    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
    )

    assert result.valid is False
    assert any(
        "path" in error.lower()
        for error in result.errors
    )


def test_patch_that_does_not_match_original_source_is_rejected():
    different_original = "value = 100\n"
    different_updated = "value = 200\n"

    diff = unified_diff(
        different_original,
        different_updated,
        filename="example.py",
    )

    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
    )

    assert result.valid is False
    assert result.applied is False


def test_python_syntax_error_is_detected():
    original = "value = 1\n"
    invalid_updated = "value = (\n"

    diff = unified_diff(
        original,
        invalid_updated,
        filename="example.py",
    )

    result = validate_unified_diff(
        original_source=original,
        diff_text=diff,
        expected_file_path="example.py",
    )

    assert result.applied is True
    assert result.valid is False
    assert result.python_syntax_valid is False
    assert any(
        "syntax error" in error.lower()
        for error in result.errors
    )


def test_path_traversal_is_rejected():
    diff = unified_diff(
        ORIGINAL_CODE,
        SAFE_CODE,
        filename="../example.py",
    )

    result = validate_unified_diff(
        original_source=ORIGINAL_CODE,
        diff_text=diff,
        expected_file_path="example.py",
    )

    assert result.valid is False
    assert any(
        "unsafe patch path" in error.lower()
        for error in result.errors
    )


def test_validator_rejects_patch_approved_by_critic_but_incomplete():
    original = '''import sqlite3

def fetch_user(user_id):
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()

    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    result = cursor.fetchone()
    connection.close()
    return result
'''

    # Reproduces the essential defect from our real Qwen experiment:
    # the diff assumes the safe query already exists in the original file.
    incomplete_diff = '''--- submitted.py
+++ submitted.py
@@ -7,5 +7,5 @@ def fetch_user(user_id):
     cursor = connection.cursor()

     query = "SELECT * FROM users WHERE id = ?"
-    cursor.execute(query)
+    cursor.execute(query, (user_id,))

     result = cursor.fetchone()
     connection.close()
     return result
'''

    result = validate_unified_diff(
        original_source=original,
        diff_text=incomplete_diff,
        expected_file_path="submitted.py",
    )

    assert result.valid is False
    assert result.applied is False
    assert any(
        "cannot be applied" in error.lower()
        for error in result.errors
    )
