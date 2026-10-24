"""Unit tests for git diff parser and changed-line mapper (Milestone 2)."""

import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.diff_parser import get_diff, is_excluded_path, parse_diff_output


class TestPathExclusion:
    """Tests for is_excluded_path filter."""

    def test_lockfiles_excluded(self):
        assert is_excluded_path("package-lock.json") is True
        assert is_excluded_path("poetry.lock") is True
        assert is_excluded_path("frontend/yarn.lock") is True
        assert is_excluded_path("pnpm-lock.yaml") is True

    def test_binary_assets_excluded(self):
        assert is_excluded_path("static/logo.png") is True
        assert is_excluded_path("assets/banner.jpg") is True
        assert is_excluded_path("docs/manual.pdf") is True
        assert is_excluded_path("archive.zip") is True

    def test_virtualenv_and_build_dirs_excluded(self):
        assert is_excluded_path(".venv/lib/site-packages/pkg.py") is True
        assert is_excluded_path("venv/bin/activate") is True
        assert is_excluded_path("node_modules/lodash/index.js") is True
        assert is_excluded_path("dist/bundle.js") is True
        assert is_excluded_path("build/lib/module.py") is True

    def test_valid_source_files_not_excluded(self):
        assert is_excluded_path("src/app.py") is False
        assert is_excluded_path("config/aws.py") is False
        assert is_excluded_path("requirements.txt") is False
        assert is_excluded_path("package.json") is False
        assert is_excluded_path("src/utils/helpers.py") is False


class TestDiffParser:
    """Tests for parse_diff_output."""

    def test_single_file_single_hunk(self):
        raw_diff = """diff --git a/app/db.py b/app/db.py
index abc1234..def5678 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,0 +11,2 @@
+def query_users(user_id):
+    return db.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 1
        diff_file = result[0]
        assert diff_file.file_path == "app/db.py"
        assert len(diff_file.added_lines) == 2
        assert diff_file.added_lines[11] == "def query_users(user_id):"
        assert (
            diff_file.added_lines[12]
            == "    return db.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")"
        )

    def test_single_file_multi_hunk(self):
        raw_diff = """diff --git a/src/service.py b/src/service.py
--- a/src/service.py
+++ b/src/service.py
@@ -5,1 +5,1 @@
-old_config = False
+new_config = True
@@ -25,0 +26,2 @@
+def cleanup():
+    pass
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 1
        diff_file = result[0]
        assert diff_file.file_path == "src/service.py"
        assert len(diff_file.added_lines) == 3
        assert diff_file.added_lines[5] == "new_config = True"
        assert diff_file.added_lines[26] == "def cleanup():"
        assert diff_file.added_lines[27] == "    pass"

    def test_new_file_creation(self):
        raw_diff = """diff --git a/src/new_mod.py b/src/new_mod.py
new file mode 100644
--- /dev/null
+++ b/src/new_mod.py
@@ -0,0 +1,3 @@
+import sys
+
+print("initial")
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 1
        assert result[0].file_path == "src/new_mod.py"
        assert result[0].added_lines[1] == "import sys"
        assert result[0].added_lines[2] == ""
        assert result[0].added_lines[3] == 'print("initial")'

    def test_deleted_file_skipped(self):
        raw_diff = """diff --git a/src/obsolete.py b/src/obsolete.py
deleted file mode 100644
--- a/src/obsolete.py
+++ /dev/null
@@ -1,5 +0,0 @@
-def dead_code():
-    pass
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 0

    def test_excluded_files_filtered(self):
        raw_diff = """diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -1 +1 @@
+{"name": "test"}
diff --git a/assets/icon.png b/assets/icon.png
Binary files a/assets/icon.png and b/assets/icon.png differ
diff --git a/src/main.py b/src/main.py
--- a/src/main.py
+++ b/src/main.py
@@ -1,0 +2 @@
+print("hello")
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 1
        assert result[0].file_path == "src/main.py"
        assert result[0].added_lines[2] == 'print("hello")'

    def test_deletions_only_produce_no_diff_file(self):
        raw_diff = """diff --git a/src/clean.py b/src/clean.py
--- a/src/clean.py
+++ b/src/clean.py
@@ -10,3 +10,0 @@
-line1
-line2
-line3
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 0

    def test_context_and_no_newline_indicator(self):
        raw_diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -10,3 +10,3 @@
 context_line
-old_line
+new_line
\\ No newline at end of file
"""
        result = parse_diff_output(raw_diff)
        assert len(result) == 1
        assert result[0].file_path == "app.py"
        # Hunk started at 10; context line is line 10; deleted line is skipped; new line is 11
        assert result[0].added_lines[11] == "new_line"

    def test_physical_file_filtering_with_repo_root(self, tmp_path: Path):
        # Create one existing file, leave the other missing
        real_file = tmp_path / "exists.py"
        real_file.write_text("print('exists')")

        raw_diff = """diff --git a/exists.py b/exists.py
--- a/exists.py
+++ b/exists.py
@@ -1,0 +2 @@
+print('exists')
diff --git a/nonexistent.py b/nonexistent.py
--- a/nonexistent.py
+++ b/nonexistent.py
@@ -1,0 +2 @@
+print('ghost')
"""
        result = parse_diff_output(raw_diff, repo_root=tmp_path, verify_physical_exists=True)
        assert len(result) == 1
        assert result[0].file_path == "exists.py"


class TestGetDiffSubprocess:
    """Tests for get_diff executing git diff subprocess."""

    @patch("subprocess.run")
    def test_get_diff_success(self, mock_run: MagicMock):
        fake_output = """diff --git a/src/hello.py b/src/hello.py
--- a/src/hello.py
+++ b/src/hello.py
@@ -1,0 +2 @@
+print('mocked')
"""
        mock_run.return_value = MagicMock(
            stdout=fake_output,
            returncode=0,
        )

        files = get_diff("base_sha", "head_sha")
        assert len(files) == 1
        assert files[0].file_path == "src/hello.py"
        assert files[0].added_lines[2] == "print('mocked')"
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["git", "diff", "--unified=0", "base_sha...head_sha"]

    @patch("subprocess.run")
    def test_get_diff_called_process_error(self, mock_run: MagicMock):
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=128, cmd="git diff", stderr="fatal: bad revision"
        )
        with pytest.raises(RuntimeError) as exc_info:
            get_diff("invalid_base", "invalid_head")
        assert "Git diff execution failed with exit code 128" in str(exc_info.value)
        assert "fatal: bad revision" in str(exc_info.value)

    @patch("subprocess.run")
    def test_get_diff_git_not_found(self, mock_run: MagicMock):
        mock_run.side_effect = FileNotFoundError("git not found")
        with pytest.raises(RuntimeError) as exc_info:
            get_diff("base", "head")
        assert "git executable not found in system PATH" in str(exc_info.value)


class TestDiffParserBenchmark:
    """Benchmark SLA verification: parsing diff completes in < 250 ms for 20 files."""

    def test_diff_parser_latency_benchmark(self):
        # Generate synthetic 20-file diff with multiple hunks per file
        diff_chunks = []
        for i in range(20):
            diff_chunks.append(f"""diff --git a/file_{i}.py b/file_{i}.py
--- a/file_{i}.py
+++ b/file_{i}.py
@@ -10,0 +11,5 @@
+line_{i}_1
+line_{i}_2
+line_{i}_3
+line_{i}_4
+line_{i}_5
@@ -50,1 +55,2 @@
-old_code
+new_code_{i}
+extra_code_{i}
""")
        large_diff = "\n".join(diff_chunks)

        start_time = time.perf_counter()
        results = parse_diff_output(large_diff)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        assert len(results) == 20
        # Budget is 250 ms per TRACKER.md and 300 ms per ARCHITECTURE.md
        assert duration_ms < 250.0, f"Diff parsing took {duration_ms:.2f} ms (budget: < 250 ms)"
