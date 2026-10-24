"""Unit tests for the Python AST Static Security Analyzer (Milestones 4 & 5)."""

import time

from src.ast_analyzer import (
    scan_diff_file_ast,
    scan_diff_for_ast_vulnerabilities,
    scan_python_source,
)
from src.models import DiffFile, ScannerCategory, Severity


class TestASTExecutionSinks:
    """Tests for AST-001 (Dangerous execution sinks: eval, exec, compile)."""

    def test_eval_detected(self):
        source = "result = eval(user_input)"
        findings = scan_python_source("calc.py", source, added_lines={1})
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "AST-001"
        assert f.severity == Severity.CRITICAL
        assert f.category == ScannerCategory.AST_OWASP
        assert "eval" in f.description

    def test_exec_detected(self):
        source = "exec(dynamic_script)"
        findings = scan_python_source("runner.py", source, added_lines={1})
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-001"

    def test_compile_detected(self):
        source = "code_obj = compile(source_str, 'test.py', 'exec')"
        findings = scan_python_source("compiler.py", source, added_lines={1})
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-001"

    def test_eval_in_comment_and_docstring_ignored(self):
        # Critical false-positive reduction check: comments and docstrings produce ZERO findings
        source = '''# Notice: Do not use eval() here because it is dangerous!
"""Module documentation explaining how exec() and eval() work."""

def safe_handler():
    # Another comment mentioning eval(payload)
    """Docstring mentioning eval() and exec()."""
    return True
'''
        findings = scan_python_source("doc_test.py", source, added_lines=set(range(1, 10)))
        assert len(findings) == 0

    def test_ast_literal_eval_allowed(self):
        source = "import ast\nparsed = ast.literal_eval(safe_payload)"
        findings = scan_python_source("safe_eval.py", source, added_lines={1, 2})
        assert len(findings) == 0


class TestInsecureDeserialization:
    """Tests for AST-002 (Insecure Deserialization: pickle, unsafe yaml.load)."""

    def test_pickle_loads_and_load_detected(self):
        source = """import pickle
data = pickle.loads(untrusted_stream)
obj = pickle.load(file_handle)
"""
        findings = scan_python_source("deser.py", source, added_lines={2, 3})
        assert len(findings) == 2
        assert findings[0].rule_id == "AST-002"
        assert findings[1].rule_id == "AST-002"
        assert findings[0].severity == Severity.CRITICAL

    def test_yaml_load_without_safeloader_detected(self):
        source = """import yaml
config1 = yaml.load(raw_yaml)
config2 = yaml.load(raw_yaml, Loader=yaml.Loader)
"""
        findings = scan_python_source("loader.py", source, added_lines={2, 3})
        assert len(findings) == 2
        assert findings[0].rule_id == "AST-002"
        assert findings[1].rule_id == "AST-002"

    def test_yaml_safeloader_and_safe_load_allowed(self):
        source = """import yaml
config1 = yaml.safe_load(raw_yaml)
config2 = yaml.load(raw_yaml, Loader=yaml.SafeLoader)
config3 = yaml.load(raw_yaml, yaml.CSafeLoader)
"""
        findings = scan_python_source("safe_yaml.py", source, added_lines={2, 3, 4})
        assert len(findings) == 0


class TestCommandInjection:
    """Tests for AST-003 (Command injection / shell=True)."""

    def test_subprocess_shell_true_detected(self):
        source = """import subprocess
subprocess.run("ls -la " + target, shell=True)
subprocess.Popen("rm -rf " + target, shell=True)
"""
        findings = scan_python_source("sub.py", source, added_lines={2, 3})
        assert len(findings) == 2
        assert findings[0].rule_id == "AST-003"
        assert findings[0].severity == Severity.HIGH
        assert findings[1].rule_id == "AST-003"

    def test_subprocess_safe_list_allowed(self):
        source = """import subprocess
subprocess.run(["ls", "-la", target])
subprocess.run(["echo", "hi"], shell=False)
"""
        findings = scan_python_source("safe_sub.py", source, added_lines={2, 3})
        assert len(findings) == 0

    def test_os_system_and_popen_detected(self):
        source = """import os
os.system("echo " + user_arg)
stream = os.popen("cat " + user_arg)
"""
        findings = scan_python_source("os_call.py", source, added_lines={2, 3})
        assert len(findings) == 2
        assert findings[0].rule_id == "AST-003"
        assert findings[1].rule_id == "AST-003"


class TestSQLInjectionDetection:
    """Tests for AST-004 (OWASP SQL Injection via dynamic query construction)."""

    def test_sqli_fstring_detected(self):
        source = "cursor.execute(f\"SELECT * FROM users WHERE id = '{uid}'\")"
        findings = scan_python_source("db.py", source, added_lines={1})
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "AST-004"
        assert f.severity == Severity.CRITICAL
        assert "f-string" in f.description

    def test_sqli_string_concat_detected(self):
        source = 'cursor.execute("SELECT * FROM items WHERE name = " + user_name)'
        findings = scan_python_source("db.py", source, added_lines={1})
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-004"
        assert "concatenation" in findings[0].description

    def test_sqli_modulo_format_detected(self):
        source = "cursor.execute('DELETE FROM users WHERE email = %s' % user_email)"
        findings = scan_python_source("db.py", source, added_lines={1})
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-004"
        assert "modulo" in findings[0].description

    def test_sqli_str_format_call_detected(self):
        source = 'cursor.raw("UPDATE users SET role = {} WHERE id = {}".format(role, uid))'
        findings = scan_python_source("db.py", source, added_lines={1})
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-004"
        assert "format()" in findings[0].description

    def test_safe_parameterized_queries_allowed(self):
        # Critical requirement: Safe parameterized queries must pass with ZERO findings!
        source = """cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
cursor.execute("INSERT INTO items (name, qty) VALUES (%s, %s)", (name, qty))
cursor.executemany("INSERT INTO records VALUES (?, ?)", [(1, 2), (3, 4)])
session.execute("SELECT * FROM orders WHERE customer_id = :cid", {"cid": cid})
"""
        findings = scan_python_source("safe_db.py", source, added_lines={1, 2, 3, 4})
        assert len(findings) == 0

    def test_non_sql_dynamic_formatting_allowed(self):
        source = """logger.info(f"User {uid} logged in from {ip}")
msg = "Result: " + str(total_score)
print("Welcome, {}".format(user_name))
"""
        findings = scan_python_source("logs.py", source, added_lines={1, 2, 3})
        assert len(findings) == 0


class TestHardcodedCredentialsAndWeakHash:
    """Tests for AST-005 (Hardcoded secrets) and AST-006 (Weak cryptographic hashes)."""

    def test_hardcoded_password_assignment_detected(self):
        source = """DB_PASSWORD = "SuperSecretPassword123!"
api_key = "a1b2c3d4e5f6a7b8c9d0"
access_token: str = "tok_live_12345"
"""
        findings = scan_python_source("creds.py", source, added_lines={1, 2, 3})
        assert len(findings) == 3
        for f in findings:
            assert f.rule_id == "AST-005"
            assert f.severity == Severity.HIGH

    def test_getenv_assignment_allowed(self):
        source = """import os
DB_PASSWORD = os.getenv("DB_PASSWORD")
api_key = os.environ.get("API_KEY")
empty_password = ""
"""
        findings = scan_python_source("env_creds.py", source, added_lines={2, 3, 4})
        assert len(findings) == 0

    def test_weak_hash_md5_sha1_detected(self):
        source = """import hashlib
h1 = hashlib.md5(data)
h2 = hashlib.sha1(data)
"""
        findings = scan_python_source("hashing.py", source, added_lines={2, 3})
        assert len(findings) == 2
        assert findings[0].rule_id == "AST-006"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[1].rule_id == "AST-006"

    def test_hashlib_safe_sha256_or_usedforsecurity_false_allowed(self):
        source = """import hashlib
h1 = hashlib.sha256(data)
h2 = hashlib.md5(data, usedforsecurity=False)
"""
        findings = scan_python_source("safe_hash.py", source, added_lines={2, 3})
        assert len(findings) == 0


class TestDiffLineScopingAndResilience:
    """Tests for line scoping, error resilience, and benchmarking."""

    def test_sinks_on_unmodified_lines_ignored(self):
        source = """# Unmodified line 1
eval(old_dangerous_code)
# Modified line 3 below
safe_new_code = 42
"""
        # Only line 3 was added in the PR diff!
        findings = scan_python_source("app.py", source, added_lines={3})
        # The eval on line 2 must be IGNORED because it was not added in the PR
        assert len(findings) == 0

    def test_syntax_error_handled_gracefully(self, capsys):
        malformed_source = "def broken_syntax(x\n    return x +"
        findings = scan_python_source("broken.py", malformed_source, added_lines={1, 2})
        assert len(findings) == 0
        captured = capsys.readouterr()
        assert "AST Syntax Warning" in captured.err

    def test_scan_diff_file_ast_synthetic(self):
        diff = DiffFile(
            file_path="src/vulnerable.py",
            added_lines={
                1: "cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
                5: "eval(payload)",
            },
        )
        findings = scan_diff_file_ast(diff)
        assert len(findings) == 2
        rule_ids = {f.rule_id for f in findings}
        assert "AST-004" in rule_ids
        assert "AST-001" in rule_ids

    def test_ast_latency_benchmark(self):
        # 20 files with 50 lines each containing mixed safe/vulnerable code
        diff_files = []
        for i in range(20):
            diff_files.append(
                DiffFile(
                    file_path=f"module_{i}.py",
                    added_lines={
                        1: "import os",
                        2: f"cursor.execute(f'SELECT * FROM table_{i} WHERE col = {{val}}')",
                        10: f"clean_var_{i} = 100",
                        20: "eval(x)",
                    },
                )
            )

        start = time.perf_counter()
        findings = scan_diff_for_ast_vulnerabilities(diff_files)
        duration_ms = (time.perf_counter() - start) * 1000.0

        assert len(findings) == 40  # 2 findings per file * 20 files
        assert duration_ms < 450.0, f"AST scanning took {duration_ms:.2f} ms (budget: < 450 ms)"

    def test_non_python_file_ignored(self):
        diff = DiffFile(file_path="config.json", added_lines={1: '{"key": "value"}'})
        findings = scan_diff_file_ast(diff)
        assert findings == []

    def test_physical_disk_file_read(self, tmp_path):
        py_file = tmp_path / "src" / "service.py"
        py_file.parent.mkdir(parents=True, exist_ok=True)
        py_file.write_text("import os\n\nos.system('ls')\n", encoding="utf-8")

        diff = DiffFile(
            file_path="src/service.py",
            added_lines={3: "os.system('ls')"},
        )
        findings = scan_diff_file_ast(diff, repo_root=tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AST-003"

    def test_attribute_credential_assignment(self):
        source = """class Config:
    def __init__(self):
        self.password = "supersecret123"
        self.api_key: str = "key_secret_999"
"""
        findings = scan_python_source("config.py", source, added_lines={3, 4})
        assert len(findings) == 2
        assert findings[0].rule_id == "AST-005"
        assert findings[1].rule_id == "AST-005"

    def test_unusual_call_expressions_handled(self):
        source = """funcs = [print]
(funcs[0])("hello")
"""
        findings = scan_python_source("odd.py", source, added_lines={2})
        assert findings == []
