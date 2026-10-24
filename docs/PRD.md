# Product Requirements Document (PRD): Automated GitHub PR Security Audit Bot

## 1. Document Purpose & AI Anti-Hallucination Directive
**CRITICAL INSTRUCTION FOR AI AGENTS:** 
This document is the single source of truth for the **Automated GitHub PR Security Audit Bot**. 
- **DO NOT** invent, assume, or extrapolate features not explicitly listed in this document.
- **DO NOT** add databases (PostgreSQL, Redis, SQLite, MongoDB), web servers (FastAPI, Flask, Express), or paid LLM APIs (OpenAI, Anthropic).
- **DO NOT** scan entire repositories when executing in Pull Request mode; scan **strictly** the modified lines extracted from the unified `git diff`.
- Every feature, formula, threshold, and benchmark in this PRD is strictly aligned with verifiable portfolio metrics and must be implemented deterministically.

---

## 2. Project Overview
The **Automated GitHub PR Security Audit Bot** is a zero-configuration, containerized CI/CD static security analysis tool written in **Python 3.11+**. It runs automatically inside **GitHub Actions** whenever a Pull Request is opened, updated (`synchronize`), or reopened. 

The bot inspects only the modified lines of code (`git diff`) and dependency manifests (`requirements.txt`, `package.json`) to detect:
1. **OWASP Top-10 Code Vulnerabilities** via Python Abstract Syntax Tree (`ast`) static analysis.
2. **Hardcoded Secrets & Cloud Credentials** via a hybrid Compiled Regex + Shannon Entropy (`> 4.5 bits/char`) scanner.
3. **Vulnerable Third-Party Dependencies (CVEs)** via single-request batch queries to the **OSV.dev REST API**.

Finally, it posts or updates a single, idempotent, line-level Markdown review comment directly on the GitHub Pull Request and blocks the PR merge (`sys.exit(1)`) if any `CRITICAL` or `HIGH` severity vulnerability is detected.

---

## 3. Target Users & Use Cases
| Target Persona | Core Need | How the Bot Delivers |
| :--- | :--- | :--- |
| **Repository Maintainers & DevSecOps Engineers** | Prevent leaked AWS keys, SQL injection, and vulnerable packages from being merged into `main` without slowing down CI pipelines. | Completes full PR diff audits in **< 4.8 seconds** and blocks merges automatically on `CRITICAL`/`HIGH` findings. |
| **Software Developers (PR Authors)** | Receive actionable, low-noise security feedback directly on the PR without sifting through false alarms on comments or docstrings. | Uses Python `ast.NodeVisitor` to reduce false positives by **74%** compared to regex-only scanners and provides copy-pasteable remediation snippets. |
| **Open-Source Project Owners** | Drop-in security scanning across multiple repositories with zero external SaaS subscriptions or host dependencies. | Runs inside an isolated Docker container triggered by a single `.github/workflows/security-audit.yml` file using the built-in `GITHUB_TOKEN`. |

---

## 4. Hard Performance & Accuracy Requirements (Non-Negotiable SLAs)
The implementation and accompanying `benchmark.py` test suite **must** achieve and verify these exact metrics:

1. **Total PR Scan Execution Time:** `< 4.8 seconds` per Pull Request (achieved by scanning only `git diff --unified=0` added lines and executing a single batch HTTP request for dependencies).
2. **AST Static Analyzer Accuracy:** `>= 96.4%` True-Positive Detection Rate on the evaluation corpus.
3. **False-Positive Reduction:** `>= 74%` reduction in false positives compared to a baseline regex-only scanner (by ignoring keywords like `eval` or `SELECT` inside comments, docstrings, and safe parameterized queries).
4. **Secret Scanner Threshold & Recall:** Shannon entropy threshold strictly set to `> 4.5 bits/char` (on candidate string literals $\ge 20$ characters) combined with compiled regex patterns, achieving a `0%` secret leak rate (`100%` recall) across `500+` synthetic test commit payloads.
5. **OSV.dev Dependency Audit Latency:** `< 650 ms` network query time for up to 50 dependencies by strictly using the batch endpoint (`POST https://api.osv.dev/v1/querybatch`).

---

## 5. Core Functional Requirements (FR)

### FR-1: Git Diff Extraction & Line Mapping (`src/diff_parser.py`)
- **Input:** Base commit SHA (`--base`) and Head commit SHA (`--head`), or a raw unified diff string/file for offline testing.
- **Behavior:**
  - Execute `git diff --unified=0 <base>...<head>` via `subprocess.run`.
  - Parse unified diff hunk headers (`@@ -old_start,old_count +new_start,new_count @@`).
  - Map every added line (`+`, excluding `+++` file headers) to its exact relative `file_path` and physical line number in the head commit.
  - Exclude binary files, deleted files, lockfiles (`package-lock.json`, `poetry.lock`, `yarn.lock`), virtual environments (`.venv/`, `node_modules/`), and `.git/` directories.
- **Output:** A dictionary mapping `{ "file_path": {set_of_added_line_numbers} }` and `{ "file_path": [(line_number, raw_line_content)] }`.

### FR-2: Hybrid Secret Scanner (`src/secret_scanner.py`)
- **Input:** Added lines from `diff_parser.py`.
- **Behavior:**
  - **Tier 1 (Compiled Regex Engine):** Detect structured credentials using pre-compiled regular expressions:
    - `SEC-001`: AWS Access Key ID (`AKIA[0-9A-Z]{16}`) — Severity: `CRITICAL`
    - `SEC-002`: AWS Secret Access Key / High-entropy assignment — Severity: `CRITICAL`
    - `SEC-003`: GitHub Personal Access Token (`ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}`) — Severity: `CRITICAL`
    - `SEC-004`: Private Cryptographic Key Header (`-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----`) — Severity: `CRITICAL`
    - `SEC-005`: JSON Web Token (`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`) — Severity: `HIGH`
    - `SEC-006`: Slack Webhook / Bot Token (`xox[baprs]-[0-9a-zA-Z]{10,48}`) — Severity: `HIGH`
  - **Tier 2 (Shannon Entropy Calculator):**
    - Extract quoted string literals of length $\ge 20$ characters that do not contain whitespace.
    - Calculate Shannon Entropy using the exact formula:
      $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
    - Flag any string literal with $H(X) > 4.5$ bits/char as `SEC-007` (High-Entropy Secret Token — Severity: `HIGH`).
  - **Tier 3 (Allowlist & False-Positive Suppression):**
    - Ignore standard UUIDs, SHA-1/SHA-256 hex hashes without secret variable context, file/URL paths (`/usr/local/...`, `https://...`), CSS hex colors, and explicit dummy placeholders (`YOUR_API_KEY`, `REPLACE_ME`, `example_token`, `test_secret`).
  - **Mandatory Redaction:**
    - Never output raw secrets in logs or PR comments. Mask all detected secrets keeping only the first 4 and last 4 characters (e.g., `AKIA************7X9Q`).

### FR-3: Python AST Static Security Analyzer (`src/ast_analyzer.py`)
- **Input:** Modified `.py` files and their set of added line numbers from `diff_parser.py`.
- **Behavior:**
  - Parse the Python source file into an Abstract Syntax Tree via `ast.parse()` and traverse nodes using a custom `ast.NodeVisitor` subclass.
  - **Only emit a finding if `node.lineno` is present in the PR's added line numbers** for that file.
  - **Vulnerability Rules:**
    - `AST-001` (**Dangerous Code Execution Sink** — `CRITICAL`): Calls to `eval()`, `exec()`, or `compile()`.
    - `AST-002` (**Insecure Deserialization** — `CRITICAL`): Calls to `pickle.loads()`, `pickle.load()`, `cPickle.loads()`, or `yaml.load()` where `Loader` is missing or not `SafeLoader`.
    - `AST-003` (**Command Injection / Shell Execution** — `HIGH`): Calls to `os.system()`, `os.popen()`, or `subprocess.run` / `Popen` / `call` / `check_output` with keyword argument `shell=True`.
    - `AST-004` (**SQL Injection via Dynamic String Construction** — `CRITICAL`): Calls to `.execute()`, `.executemany()`, or `.raw()` where the first query argument contains SQL keywords (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`) and is constructed dynamically using:
      - f-strings (`ast.JoinedStr`)
      - String concatenation (`ast.BinOp` with `ast.Add`)
      - Modulo interpolation (`ast.BinOp` with `ast.Mod`)
      - `.format()` method call (`ast.Call` where `func.attr == "format"`)
      - *Note:* Safe parameterized queries (e.g., `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))`) **must** pass with zero warnings.
    - `AST-005` (**Hardcoded Password/Secret Assignment** — `HIGH`): `ast.Assign` or `ast.AnnAssign` where the target variable name matches `(password|passwd|secret|api_key|private_key|access_token)` and the assigned value is a non-empty `ast.Constant` string literal (ignoring `os.getenv` or `os.environ` lookups).
    - `AST-006` (**Weak Cryptographic Hash** — `MEDIUM`): Calls to `hashlib.md5()` or `hashlib.sha1()` outside of non-security contexts.

### FR-4: Batch Dependency Vulnerability Scanner (`src/dep_scanner.py`)
- **Input:** Modified `requirements.txt` and/or `package.json` files detected in the PR diff.
- **Behavior:**
  - Parse pinned package names and exact version numbers from `requirements.txt` (`PyPI` ecosystem, e.g., `requests==2.19.0`) and `package.json` `dependencies` / `devDependencies` (`npm` ecosystem, stripping `^` and `~`).
  - Construct a single batch request payload and send a `POST` request to `https://api.osv.dev/v1/querybatch` with a 3-second timeout.
  - Map returned vulnerability records (`CVE-...` / `GHSA-...`) to `CRITICAL`, `HIGH`, or `MEDIUM` severity and extract the fixed version string.
  - Complete the batch network check in **< 650 ms**.

### FR-5: Aggregation, Policy Gate & PR Review Commenter (`src/pr_commenter.py` & `src/main.py`)
- **Behavior:**
  - Deduplicate findings by `(file_path, line_number, rule_id)` and sort by severity (`CRITICAL` $\rightarrow$ `HIGH` $\rightarrow$ `MEDIUM`).
  - Render a deterministic Markdown report containing:
    - Hidden idempotency marker: `<!-- security-audit-bot-v1 -->`
    - Header badge (`❌ Action Required` or `✅ Passed`), total scan latency (`scan_duration_ms`), and severity summary counters.
    - Markdown table with columns: `Severity`, `Rule ID`, `Location (File:Line)`, `Vulnerability Description`, and `Suggested Fix`.
  - **Idempotent GitHub API Upsert:**
    - Query `GET /repos/{owner}/{repo}/issues/{pr_number}/comments`.
    - If a comment containing `<!-- security-audit-bot-v1 -->` exists, update it via `PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}`.
    - Otherwise, create a new comment via `POST /repos/{owner}/{repo}/issues/{pr_number}/comments`.
  - **CI Policy Exit Code:**
    - Exit with code `1` (`sys.exit(1)`) if $\ge 1$ `CRITICAL` or `HIGH` finding exists (blocking the PR merge).
    - Exit with code `0` (`sys.exit(0)`) if zero `CRITICAL`/`HIGH` findings exist.

---

## 6. Strict Out-of-Scope Boundaries (What NOT to Build)
To prevent scope creep and AI hallucination, the following are **strictly forbidden**:
1. **No Web Frontend or Dashboard:** The UI of this project is the rendered GitHub Pull Request Markdown comment and the CLI terminal output (plus an optional static HTML report export for local preview). Do not build a React/Vue/Streamlit app.
2. **No Database Layer:** Do not add PostgreSQL, SQLite, or Redis. The bot is a stateless CI/CD CLI runner.
3. **No External LLM Calls:** Remediation suggestions must be deterministic, rule-based templates defined in Python dictionaries—no OpenAI or Anthropic API dependencies.
4. **No Third-Party Security Wrappers:** Do not wrap `bandit`, `semgrep`, `trufflehog`, or `pip-audit` under the hood. All AST visitors, entropy math, and OSV.dev batch HTTP calls must be written from first principles in `src/`.