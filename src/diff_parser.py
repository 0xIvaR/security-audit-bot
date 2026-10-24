"""Git diff parser and changed-line mapper.

Executes 'git diff --unified=0 <base>...<head>' and parses unified diff hunk headers
to map newly added lines ('+' lines) to physical 1-based line numbers in DiffFile models.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from src.models import DiffFile

# ---------------------------------------------------------------------------
# Path & File Exclusion Rules (ARCHITECTURE.md Section 6.1 & PRD FR-1)
# ---------------------------------------------------------------------------
EXCLUDED_EXTENSIONS: set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".bin",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
}

EXCLUDED_LOCKFILES: set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
}

EXCLUDED_DIR_NAMES: set[str] = {
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".git",
    "__pycache__",
}

# Unified diff parsing regexes
HUNK_HEADER_RE: re.Pattern[str] = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
GIT_DIFF_HEADER_RE: re.Pattern[str] = re.compile(r"^diff --git a/(.*) b/(.*)$")
FILE_HEADER_OLD_RE: re.Pattern[str] = re.compile(r"^--- (?:a/)?(.*)$")
FILE_HEADER_NEW_RE: re.Pattern[str] = re.compile(r"^\+\+\+ (?:b/)?(.*)$")


def is_excluded_path(file_path: str) -> bool:
    """Determine whether a file path should be excluded from security analysis.

    Excludes binary files, lockfiles, virtual environments, and build artifacts.
    """
    clean_path = file_path.replace("\\", "/").strip()
    path_obj = Path(clean_path)

    # Exclude lockfiles by filename
    if path_obj.name in EXCLUDED_LOCKFILES:
        return True

    # Exclude binary / asset files by extension
    if path_obj.suffix.lower() in EXCLUDED_EXTENSIONS:
        return True

    # Exclude directories
    for part in path_obj.parts:
        if part in EXCLUDED_DIR_NAMES:
            return True

    return False


def parse_diff_output(
    diff_text: str,
    repo_root: str | Path | None = None,
    verify_physical_exists: bool = False,
) -> list[DiffFile]:
    """Parse raw unified diff text into a list of DiffFile domain models.

    Args:
        diff_text: Raw output of 'git diff --unified=0'.
        repo_root: Optional filesystem root path to verify physical file existence.
        verify_physical_exists: If True, only retain files that physically exist on disk.

    Returns:
        List of DiffFile instances containing mapped 1-based line numbers.
    """
    diff_files: list[DiffFile] = []
    lines = diff_text.splitlines()

    current_file_path: str | None = None
    is_deleted_file: bool = False
    added_lines: dict[int, str] = {}
    current_line_num: int = 0
    in_hunk: bool = False

    def finalize_current_file() -> None:
        nonlocal current_file_path, added_lines, is_deleted_file
        if current_file_path and not is_deleted_file and added_lines:
            normalized_path = current_file_path.replace("\\", "/").strip()
            if not is_excluded_path(normalized_path):
                # If verify_physical_exists is True, check if file exists on disk
                if verify_physical_exists:
                    root = Path(repo_root) if repo_root else Path.cwd()
                    target_physical_path = root / normalized_path
                    if not target_physical_path.exists():
                        current_file_path = None
                        added_lines = {}
                        is_deleted_file = False
                        return

                diff_files.append(
                    DiffFile(file_path=normalized_path, added_lines=dict(added_lines))
                )
        current_file_path = None
        added_lines = {}
        is_deleted_file = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # Check for start of a new file diff
        diff_match = GIT_DIFF_HEADER_RE.match(line)
        if diff_match:
            finalize_current_file()
            # Default target path from header b-side
            current_file_path = diff_match.group(2)
            is_deleted_file = False
            in_hunk = False
            i += 1
            continue

        # Check for old-file header '--- a/path' or '--- /dev/null'
        if line.startswith("--- "):
            old_match = FILE_HEADER_OLD_RE.match(line)
            if old_match:
                pass  # Old file header
            i += 1
            continue

        # Check for new-file header '+++ b/path' or '+++ /dev/null'
        if line.startswith("+++ "):
            new_match = FILE_HEADER_NEW_RE.match(line)
            if new_match:
                new_path = new_match.group(1).strip()
                if new_path == "/dev/null":
                    # Deleted file: do not scan
                    is_deleted_file = True
                else:
                    current_file_path = new_path
            i += 1
            continue

        # Check for hunk header '@@ -old,count +new,count @@'
        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            current_line_num = int(hunk_match.group(1))
            in_hunk = True
            i += 1
            continue

        # If inside a hunk, process line changes
        if in_hunk:
            if line.startswith("+") and not line.startswith("+++"):
                # Newly added line in PR
                raw_content = line[1:]
                added_lines[current_line_num] = raw_content
                current_line_num += 1
            elif line.startswith("-") and not line.startswith("---"):
                # Deleted line: does not increment head line counter
                pass
            elif line.startswith(" "):
                # Context line (if unified > 0)
                current_line_num += 1
            elif line.startswith("\\ No newline at end of file"):
                pass
            elif line.startswith("diff --git"):
                # Immediately transition to next file
                continue

        i += 1

    finalize_current_file()
    return diff_files


def get_diff(
    base_sha: str,
    head_sha: str,
    repo_root: str | Path | None = None,
    verify_physical_exists: bool = False,
) -> list[DiffFile]:
    """Execute 'git diff --unified=0 <base>...<head>' and return parsed DiffFiles.

    Args:
        base_sha: Base commit SHA or branch name.
        head_sha: Head commit SHA or branch name.
        repo_root: Root directory of git repository (defaults to current working directory).
        verify_physical_exists: If True, filters out files not present in working directory.

    Returns:
        List of DiffFile domain models with 1-based mapped added lines.

    Raises:
        RuntimeError: If git diff execution fails.
    """
    cwd = str(repo_root) if repo_root else os.getcwd()
    cmd = ["git", "diff", "--unified=0", f"{base_sha}...{head_sha}"]

    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
        return parse_diff_output(
            result.stdout,
            repo_root=cwd,
            verify_physical_exists=verify_physical_exists,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Git diff execution failed with exit code {exc.returncode}: {exc.stderr.strip()}"
        ) from exc
    except FileNotFoundError as exc:
        raise RuntimeError("git executable not found in system PATH.") from exc
