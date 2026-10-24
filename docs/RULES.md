# RULES.md — Engineering Standards, Anti-Hallucination & AI Directives

## 1. Document Objective & AI Directive
**MANDATORY FOR ALL AI CODING AGENTS & COLLABORATORS:**
This document defines the non-negotiable operational laws for the **Automated GitHub PR Security Audit Bot** repository. When generating, refactoring, or reviewing code:
- **DO NOT** deviate from the architectural boundaries established in `PRD.md` and `ARCHITECTURE.md`.
- **DO NOT** add unauthorized dependencies, external databases, or paid LLM APIs.
- **DO NOT** break existing data contracts (`models.py`), CLI arguments, or GitHub Action outputs.
- Every commit or code suggestion must comply with the rules set forth in this document.

---

## 2. The Five Golden Invariants (Non-Negotiable)

1. **Stateless Execution (Zero Database):**
   - The engine must remain 100% stateless. Under no circumstances should PostgreSQL, MySQL, MongoDB, SQLite, or Redis be introduced into this project.
   - Idempotency and state tracking are handled exclusively through the GitHub REST API using the invisible HTML comment anchor: `<!-- security-audit-bot-v1 -->`.

2. **Diff-Scoped Analysis (Targeted Execution):**
   - The bot must **never** perform full repository scans during a Pull Request run.
   - Analysis must be strictly scoped to modified files and newly added/modified lines (`+` lines) extracted from `git diff --unified=0 <base>...<head>`.
   - AST findings and secret alerts are only emitted if the line of violation exists within the set of added line numbers (`node.lineno in added_line_numbers`).

3. **Zero Paid LLM Dependencies:**
   - All remediation instructions, security explanations, and code fix suggestions must be deterministic strings and templates stored directly in the Python source code.
   - Never call OpenAI, Anthropic, Google Gemini, or any paid external LLM API during runtime.

4. **Zero Third-Party Scanner Wrappers:**
   - Do not wrap or execute `bandit`, `semgrep`, `trufflehog`, `safety`, or `pip-audit` via subprocess.
   - All AST syntax node visitors, Shannon entropy calculations, and CVE manifest queries must be implemented natively from first principles in `src/`.

5. **Strict Metric & SLA Preservation:**
   - Total PR scan latency must stay under **$< 4.8\text{ seconds}$**.
   - AST True-Positive Detection Rate must measure **$\ge 96.4\%$**.
   - False-positive reduction compared to regex must measure **$\ge 74\%$**.
   - Secret scanner recall must be **$100\%$ ($0\%$ leakage)** with Shannon entropy threshold strictly set to **$> 4.5\text{ bits/char}$** on literals $\ge 20$ characters.
   - OSV.dev dependency audit latency must stay under **$< 650\text{ ms}$** by utilizing the batch query API.

---

## 3. Dependency & Tooling Constraints

### 3.1 Approved Production Dependencies (`requirements.txt`)
Only the following third-party libraries are permitted in runtime environments:
- `pydantic>=2.6.0,<3.0.0` (Strict schema and contract validation)
- `requests>=2.31.0,<3.0.0` (Synchronous HTTP client for OSV.dev & GitHub REST API)

### 3.2 Approved Development & Test Dependencies
- `pytest>=8.0.0` (Unit and integration test runner)
- `pytest-cov>=4.1.0` (Test coverage tracking; minimum threshold: 85%)
- `ruff>=0.3.0` (Deterministic linter and code formatter)

### 3.3 Explicitly Prohibited Libraries
- **NO Async Web Clients:** Do not install `aiohttp`, `httpx`, or `urllib3` wrappers. Standard `requests` with connection pooling and timeouts is sufficient.
- **NO Heavy Frameworks:** Do not install `fastapi`, `flask`, `django`, `celery`, or `click`. Use standard library `argparse` for CLI commands.
- **NO Data Science / Heavy Math Bloat:** Do not install `numpy`, `scipy`, or `pandas`. Shannon entropy and math operations must use Python's built-in `math` and `collections.Counter`.

---

## 4. Security & Privacy Engineering Rules

1. **Mandatory Secret Redaction:**
   - Never log, print, or transmit raw unmasked secrets.
   - Every candidate secret matching regex or entropy thresholds must immediately pass through `redact_secret()` before being attached to a `Finding` model:
     $$\text{Masked} = s[0:4] + \text{"*"}\times 12 + s[-4:]$$
   - Example: `AKIAIOSFODNN7EXAMPLE` $\rightarrow$ `AKIA************MPLE`.

2. **GitHub Token Security & Least Privilege:**
   - The workflow file (`security-audit.yml`) must request strictly minimal permissions:
     ```yaml
     permissions:
       contents: read
       pull-requests: write
     ```
   - Never write to `contents: write` or request administrative repository access.

3. **Isolated Container Execution:**
   - The `Dockerfile` must run as a non-privileged system user (`uid: 1001`, `appuser`), never as `root`.
   - The filesystem inside the container must be mounted as read-only with ephemeral `/tmp` storage.

4. **Safe Syntax Tree Traversal:**
   - Python code must only be parsed using `ast.parse()`. Never use `eval()` or `exec()` dynamically within the audit bot codebase itself.

---

## 5. Code Quality & Architecture Standards

1. **Python 3.11+ Idioms & Strict Type Hints:**
   - Every function and method signature must include complete type annotations (`typing` module or native Python 3.10+ union types `X | Y`).
   - Use `pathlib.Path` for path manipulations instead of raw string concatenations.

2. **Schema Integrity via Pydantic v2:**
   - Never pass untyped dictionaries between internal modules (`diff_parser` $\rightarrow$ scanners $\rightarrow$ `aggregator` $\rightarrow$ `pr_commenter`).
   - All inter-module communication must use the official models: `DiffFile`, `Finding`, and `AuditReport`.

3. **Defensive Error Boundaries & Resiliency:**
   - **SyntaxError Resilience:** If a user submits malformed Python code in a PR, `ast_analyzer.py` must catch `SyntaxError`, log an informational warning to `stderr`, and continue scanning other files without terminating early.
   - **Network Timeout Handling:** Calls to external APIs (OSV.dev and GitHub) must enforce a hard timeout (`timeout=3.0` seconds). If OSV.dev times out or returns HTTP 5xx, the error must be logged non-fatally so that code-level AST and Secret findings are still posted to the PR.
   - **No Bare Excepts:** Always catch specific exceptions (`requests.RequestException`, `ast.PyCF_ONLY_AST`, `ValueError`). Never write bare `except:`.

4. **CLI Contract Immutability (`src/main.py`):**
   The CLI interface must support the following arguments without breaking compatibility:
   - `--base <commit_sha>` (Base commit for comparison)
   - `--head <commit_sha>` (Target commit containing PR changes)
   - `--repo <owner/repo>` (GitHub repository name)
   - `--pr-number <int>` (Pull Request identifier)
   - `--dry-run` (Executes full scan and outputs Markdown/ANSI to stdout without calling GitHub API)
   - `--html-report <filepath>` (Optional export of dark-mode HTML report)

---

## 6. Testing & Benchmarking Rules

1. **Deterministic Test Isolation:**
   - Unit tests under `tests/` must be 100% offline and deterministic.
   - Never make live network requests to `api.osv.dev` or `api.github.com` during `pytest`. Use `unittest.mock.patch` to mock external API responses.

2. **Confusion Matrix & Benchmark Invariance:**
   - The `benchmarks/run_benchmark.py` script must validate the exact ground-truth metrics against the 500+ synthetic commit corpus:
     - AST True-Positive Rate $\ge 96.4\%$
     - False-Positive Reduction $\ge 74\%$
     - Secret Leak Rate $= 0\%$
   - Any rule alteration that degrades these metrics below the established threshold is rejected immediately.

3. **Continuous Coverage Gate:**
   - Every new feature or scanner rule must be accompanied by corresponding unit tests.
   - Code coverage must remain $\ge 85\%$ as measured by `pytest --cov=src --cov-fail-under=85`.

---

## 7. PR Comment & Policy Gate Rules

1. **Idempotency Mandate:**
   - The bot must maintain exactly one comment thread per Pull Request.
   - It must first search for the marker `<!-- security-audit-bot-v1 -->`. If found, it updates via `PATCH`. If not found, it creates via `POST`.

2. **Merge-Blocking Policy:**
   - `sys.exit(1)` is triggered if and only if:
     $$(\text{critical\_count} + \text{high\_count}) > 0$$
   - `sys.exit(0)` is returned if only `MEDIUM` advisories or zero issues are found.
   - The bot must clearly indicate this status in the Markdown header badge (`❌ Merge Blocked` vs `✅ Passed`).

---

## 8. Git Commit & Working Protocol for AI Agents

1. **Atomic Step Progression:**
   - Never implement multiple milestones at once. Work milestone by milestone (`M1`, `M2`, `M3`, etc.).
   - Verify each milestone against its unit tests before progressing to the next.

2. **Commit Message Format:**
   Use the Conventional Commits specification:
   - `feat(ast): add JoinedStr SQL injection detection rule AST-004`
   - `fix(secrets): add UUID false-positive filter to entropy calculator`
   - `test(dep): add OSV batch query timeout mock tests`
   - `docs(specs): update MEMORY.md milestone status`

3. **No Unsolicited File Deletions:**
   - Never delete specification files (`PRD.md`, `ARCHITECTURE.md`, `DESIGN.md`, `MEMORY.md`, `RULES.md`, `TRACKER.md`) or historical logs.