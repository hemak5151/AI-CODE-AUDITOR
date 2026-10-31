
import difflib


NO_NEWLINE_MARKER = "\\ No newline at end of file"


def unified_diff(
    old: str,
    new: str,
    filename: str = "submitted.py",
) -> str:
    """
    Generate a Git-compatible unified diff.

    Correctly handles source files that do not end
    with a newline character.
    """

    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)

    generated_diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=filename,
        tofile=filename,
        lineterm="\n",
    )

    output = []

    for line in generated_diff:
        output.append(line)

        # Git requires the missing-newline marker to appear
        # on a separate line after an unterminated source line.
        if (
            line.startswith((" ", "+", "-"))
            and not line.endswith(("\n", "\r"))
        ):
            output.append("\n")
            output.append(NO_NEWLINE_MARKER)
            output.append("\n")

    return "".join(output)
