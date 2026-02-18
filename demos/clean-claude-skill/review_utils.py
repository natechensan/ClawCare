"""Helper utilities for the code review skill."""


def count_changes(diff_text: str) -> dict:
    """Count added and removed lines in a unified diff."""
    added = sum(1 for line in diff_text.splitlines() if line.startswith("+"))
    removed = sum(1 for line in diff_text.splitlines() if line.startswith("-"))
    return {"added": added, "removed": removed}


def summarize_files(diff_text: str) -> list[str]:
    """Extract file names from a unified diff."""
    files = []
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            files.append(line[6:])
    return files
