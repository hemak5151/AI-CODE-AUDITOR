import difflib

def unified_diff(old: str, new: str, filename: str = "submitted.py") -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile=filename, tofile=filename))
