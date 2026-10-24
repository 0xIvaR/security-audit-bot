"""Python AST Static Security Analyzer (Milestones 4 & 5).

Parses Python source files using native ast.NodeVisitor to detect OWASP Top-10 sinks:
- AST-001: Dangerous code execution sinks (eval, exec, compile)
- AST-002: Insecure deserialization (pickle, unsafe yaml.load)
- AST-003: Command injection (subprocess with shell=True, os.system, os.popen)
- AST-004: OWASP SQL Injection via dynamic string formatting vs safe parameterized queries
- AST-005: Hardcoded sensitive credentials assigned to variables
- AST-006: Weak cryptographic hash functions (hashlib.md5, hashlib.sha1)

Strictly filters findings by intersecting node.lineno with PR added lines (+ lines).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

from src.config import AST_RULES
from src.models import DiffFile, Finding

# SQL statement keyword pattern
SQL_KEYWORD_RE: re.Pattern[str] = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|FROM|WHERE)\b", re.IGNORECASE
)

# Sensitive variable names for hardcoded credential detection
SENSITIVE_VAR_RE: re.Pattern[str] = re.compile(
    r"(?i)(password|passwd|secret|api_key|access_token|private_key)"
)


def get_call_full_name(node: ast.Call) -> str:
    """Resolve full dotted name of a function call (e.g. 'os.system', 'pickle.loads')."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        curr = func.value
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
        return ".".join(reversed(parts))
    return ""


def extract_constants_from_expr(node: ast.AST) -> str:
    """Extract and concatenate all constant string fragments within a dynamic AST expression."""
    texts: list[str] = []

    for subnode in ast.walk(node):
        if isinstance(subnode, ast.Constant) and isinstance(subnode.value, str):
            texts.append(subnode.value)

    return " ".join(texts)


def is_dynamic_sql_construction(arg_node: ast.AST) -> tuple[bool, str]:
    """Check whether a query argument node represents dynamic string construction containing SQL keywords.

    Returns:
        (is_vulnerable, reason_description)
    """
    # 1. f-string: ast.JoinedStr
    if isinstance(arg_node, ast.JoinedStr):
        text = extract_constants_from_expr(arg_node)
        if SQL_KEYWORD_RE.search(text):
            return True, "Dynamic SQL constructed via f-string (ast.JoinedStr)"

    # 2. String concatenation or modulo formatting: ast.BinOp with Add or Mod
    if isinstance(arg_node, ast.BinOp):
        if isinstance(arg_node.op, ast.Add):
            text = extract_constants_from_expr(arg_node)
            if SQL_KEYWORD_RE.search(text):
                return True, "Dynamic SQL constructed via string concatenation (+)"
        elif isinstance(arg_node.op, ast.Mod):
            text = extract_constants_from_expr(arg_node)
            if SQL_KEYWORD_RE.search(text):
                return True, "Dynamic SQL constructed via modulo string formatting (%)"

    # 3. str.format() method call: ast.Call where func.attr == 'format'
    if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, ast.Attribute):
        if arg_node.func.attr == "format":
            text = extract_constants_from_expr(arg_node.func.value)
            if SQL_KEYWORD_RE.search(text):
                return True, "Dynamic SQL constructed via str.format() method call"

    return False, ""


def is_safe_loader_arg(node: ast.Call) -> bool:
    """Check if yaml.load call specifies a safe loader argument."""
    # Check positional args (yaml.load(data, Loader=yaml.SafeLoader) or yaml.load(data, yaml.SafeLoader))
    for arg in node.args[1:]:
        if isinstance(arg, ast.Attribute) and arg.attr in ("SafeLoader", "CSafeLoader"):
            return True
        if isinstance(arg, ast.Name) and arg.id in ("SafeLoader", "CSafeLoader"):
            return True

    for kw in node.keywords:
        if kw.arg == "Loader":
            if isinstance(kw.value, ast.Attribute) and kw.value.attr in (
                "SafeLoader",
                "CSafeLoader",
            ):
                return True
            if isinstance(kw.value, ast.Name) and kw.value.id in (
                "SafeLoader",
                "CSafeLoader",
            ):
                return True

    return False


def is_used_for_security_false(node: ast.Call) -> bool:
    """Check if hashlib call specifies usedforsecurity=False."""
    for kw in node.keywords:
        if kw.arg == "usedforsecurity":
            if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
    return False


class SecurityNodeVisitor(ast.NodeVisitor):
    """Custom AST visitor detecting OWASP Top-10 sinks and SQL injection."""

    def __init__(
        self,
        file_path: str,
        source_code: str,
        added_lines: set[int],
    ) -> None:
        self.file_path = file_path
        self.source_code = source_code
        self.added_lines = added_lines
        self.lines = source_code.splitlines()
        self.findings: list[Finding] = []

    def _get_snippet(self, lineno: int) -> str:
        """Extract source line snippet for a given line number."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _emit(
        self,
        lineno: int,
        rule_id: str,
        custom_desc: str | None = None,
        custom_snippet: str | None = None,
    ) -> None:
        """Emit a security finding if lineno exists within PR added lines."""
        if lineno not in self.added_lines:
            return

        rule_spec = AST_RULES[rule_id]
        snippet = custom_snippet if custom_snippet is not None else self._get_snippet(lineno)

        self.findings.append(
            Finding(
                file_path=self.file_path,
                line_number=lineno,
                rule_id=rule_id,
                category=rule_spec["category"],
                severity=rule_spec["severity"],
                title=rule_spec["title"],
                description=custom_desc or rule_spec["description"],
                remediation=rule_spec["remediation"],
                snippet=snippet,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:
        """Inspect function and method calls for dangerous sinks."""
        call_name = get_call_full_name(node)
        lineno = getattr(node, "lineno", 0)

        # -------------------------------------------------------------------
        # AST-001: Dangerous Code Execution Sink (eval, exec, compile)
        # -------------------------------------------------------------------
        if call_name in ("eval", "exec", "compile"):
            self._emit(
                lineno=lineno,
                rule_id="AST-001",
                custom_desc=f"Dynamic code execution sink '{call_name}()' detected.",
            )

        # -------------------------------------------------------------------
        # AST-002: Insecure Deserialization (pickle, unsafe yaml.load)
        # -------------------------------------------------------------------
        elif call_name in (
            "pickle.loads",
            "pickle.load",
            "_pickle.loads",
            "_pickle.load",
            "cPickle.loads",
            "cPickle.load",
        ):
            self._emit(
                lineno=lineno,
                rule_id="AST-002",
                custom_desc=f"Insecure deserialization call '{call_name}()' allows arbitrary object execution.",
            )
        elif call_name == "yaml.load":
            if not is_safe_loader_arg(node):
                self._emit(
                    lineno=lineno,
                    rule_id="AST-002",
                    custom_desc="Unsafe 'yaml.load()' call without SafeLoader allows remote code execution.",
                )

        # -------------------------------------------------------------------
        # AST-003: Command Injection (subprocess shell=True, os.system, os.popen)
        # -------------------------------------------------------------------
        elif call_name in ("os.system", "os.popen"):
            self._emit(
                lineno=lineno,
                rule_id="AST-003",
                custom_desc=f"Insecure shell command execution '{call_name}()' detected.",
            )
        elif any(
            call_name.startswith(prefix)
            for prefix in (
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.call",
                "subprocess.check_output",
                "subprocess.check_call",
            )
        ):
            has_shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if has_shell_true:
                self._emit(
                    lineno=lineno,
                    rule_id="AST-003",
                    custom_desc=f"Subprocess call '{call_name}' with shell=True is vulnerable to command injection.",
                )

        # -------------------------------------------------------------------
        # AST-004: OWASP SQL Injection Sink (.execute, .executemany, .raw)
        # -------------------------------------------------------------------
        method_name = ""
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr

        if method_name in ("execute", "executemany", "raw") and node.args:
            first_arg = node.args[0]
            is_vulnerable, reason = is_dynamic_sql_construction(first_arg)
            if is_vulnerable:
                self._emit(
                    lineno=lineno,
                    rule_id="AST-004",
                    custom_desc=f"SQL Injection: {reason} passed to .{method_name}().",
                )

        # -------------------------------------------------------------------
        # AST-006: Weak Cryptographic Hash Function (md5, sha1)
        # -------------------------------------------------------------------
        elif call_name in ("hashlib.md5", "hashlib.sha1"):
            if not is_used_for_security_false(node):
                self._emit(
                    lineno=lineno,
                    rule_id="AST-006",
                    custom_desc=f"Use of broken or weak cryptographic hash function '{call_name}'.",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Inspect variable assignments for hardcoded credentials (AST-005)."""
        lineno = getattr(node, "lineno", 0)

        # Verify assigned value is a non-empty string constant
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value.strip()
            if val:
                for target in node.targets:
                    target_name = ""
                    if isinstance(target, ast.Name):
                        target_name = target.id
                    elif isinstance(target, ast.Attribute):
                        target_name = target.attr

                    if target_name and SENSITIVE_VAR_RE.search(target_name):
                        self._emit(
                            lineno=lineno,
                            rule_id="AST-005",
                            custom_desc=(
                                f"Hardcoded credential assignment to sensitive variable '{target_name}'."
                            ),
                        )
                        break

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Inspect annotated variable assignments for hardcoded credentials (AST-005)."""
        lineno = getattr(node, "lineno", 0)

        if (
            node.value
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            val = node.value.value.strip()
            if val:
                target_name = ""
                if isinstance(node.target, ast.Name):
                    target_name = node.target.id
                elif isinstance(node.target, ast.Attribute):
                    target_name = node.target.attr

                if target_name and SENSITIVE_VAR_RE.search(target_name):
                    self._emit(
                        lineno=lineno,
                        rule_id="AST-005",
                        custom_desc=(
                            f"Hardcoded credential assignment to annotated variable '{target_name}'."
                        ),
                    )

        self.generic_visit(node)


def scan_python_source(file_path: str, source_code: str, added_lines: set[int]) -> list[Finding]:
    """Parse Python source code and traverse AST for security violations.

    Gracefully catches and logs SyntaxError on partially formed PR diffs without crashing.
    """
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError as exc:
        print(
            f"[!] AST Syntax Warning: Unable to parse '{file_path}' (line {exc.lineno}): {exc.msg}",
            file=sys.stderr,
        )
        return []

    visitor = SecurityNodeVisitor(
        file_path=file_path,
        source_code=source_code,
        added_lines=added_lines,
    )
    visitor.visit(tree)
    return visitor.findings


def scan_diff_file_ast(diff_file: DiffFile, repo_root: str | Path | None = None) -> list[Finding]:
    """Scan a single modified .py DiffFile by reading source and intersecting line numbers."""
    if not diff_file.file_path.endswith(".py"):
        return []

    root = Path(repo_root) if repo_root else Path.cwd()
    physical_path = root / diff_file.file_path

    # If physical file exists, read entire source to provide valid syntax tree
    if physical_path.exists():
        try:
            source_code = physical_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(
                f"[!] AST Read Warning: Unable to read '{diff_file.file_path}': {exc}",
                file=sys.stderr,
            )
            return []
    else:
        # Fallback for synthetic/offline diffs: construct source code from added lines
        max_line = max(diff_file.added_lines.keys()) if diff_file.added_lines else 0
        constructed_lines: list[str] = [""] * max_line
        for line_num, content in diff_file.added_lines.items():
            constructed_lines[line_num - 1] = content
        source_code = "\n".join(constructed_lines)

    added_line_numbers = set(diff_file.added_lines.keys())
    return scan_python_source(
        file_path=diff_file.file_path,
        source_code=source_code,
        added_lines=added_line_numbers,
    )


def scan_diff_for_ast_vulnerabilities(
    diff_files: list[DiffFile], repo_root: str | Path | None = None
) -> list[Finding]:
    """Traverse all modified .py DiffFiles in the PR diff and return consolidated AST findings."""
    all_findings: list[Finding] = []

    for diff_file in diff_files:
        all_findings.extend(scan_diff_file_ast(diff_file, repo_root=repo_root))

    return all_findings
