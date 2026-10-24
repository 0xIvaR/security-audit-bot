# TRACKER.md — Master Phase-by-Phase Execution Tracker

## Automated GitHub PR Security Audit Bot

---

## 1. Executive Status & Progress Overview

| Phase | Milestone Range | Focus Area | Status | Target Completion |
| :--- | :--- | :--- | :---: | :---: |
| **Phase 1** | **M1 – M2** | Foundation, CLI Harness & Diff Line Mapping | ⬜ Pending | Week 1 |
| **Phase 2** | **M3 – M6** | Core Detection Engines (Secrets, AST Sinks, SQLi, CVEs) | ⬜ Pending | Week 2 |
| **Phase 3** | **M7 – M9** | Policy Gate, PR Commenter & GitHub Actions CI | ⬜ Pending | Week 3 |
| **Phase 4** | **M10 – M11**| Benchmarking (500+ Commits), Pytest & Portfolio Docs | ⬜ Pending | Week 4 |

### Target Ground-Truth Metrics (Non-Negotiable SLAs)
* [ ] **Total PR Scan Latency:** $< 4.8\text{ seconds}$ per Pull Request
* [ ] **AST Static Analyzer Accuracy:** $\ge 96.4\%$ True-Positive Rate (TPR)
* [ ] **False-Positive Reduction:** $\ge 74\%$ reduction vs. regex baseline
* [ ] **Shannon Entropy Threshold:** $> 4.5\text{ bits/char}$ on candidate string literals $\ge 20$ chars
* [ ] **Secret Leak Rate:** $0\%$ leak rate ($100\%$ recall) across 500+ synthetic test commits
* [ ] **OSV.dev Batch CVE Audit:** $< 650\text{ ms}$ for batch manifest queries

---

## 2. Phase 1: Foundation, CLI Harness & Diff Line Mapping

### **M1: Environment, Project Structure & CLI Baseline**
**Goal:** Establish a clean Python 3.11+ development environment with strict typing, linting, and CLI execution harness.
* **Status:** ✅ Completed
* **Sub-tasks:**
  - [x] Initialize Git repository with `.gitignore` and `.env.example` (`GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `PR_NUMBER`)
  - [x] Configure `pyproject.toml` and lock production dependencies: `pydantic>=2.6.0,<3.0.0`, `requests>=2.31.0,<3.0.0`
  - [x] Configure dev dependencies: `pytest>=8.0.0`, `pytest-cov>=5.0.0`, `ruff>=0.3.0`
  - [x] Establish directory scaffold: `src/`, `tests/`, `benchmarks/`, `trackers/`
  - [x] Implement `src/models.py` with Pydantic v2 data models (`Severity`, `ScannerCategory`, `DiffFile`, `Finding`, `AuditReport`)
  - [x] Implement `src/main.py` CLI parser supporting `--base`, `--head`, `--repo`, `--pr-number`, `--dry-run`, and `--html-report`
* **Verification Gate:**
  - [x] `ruff check .` and `ruff format --check .` pass with zero errors
  - [x] `python -m src.main --help` returns exit code `0` with structured argument descriptions

---

### **M2: Git Diff Parser & Changed-Line Mapper**
**Goal:** Parse unified git diffs to map newly added lines (`+`) to exact physical line numbers for sub-second scanning.
* **Status:** ✅ Completed
* **Sub-tasks:**
  - [x] Implement `src/diff_parser.py` wrapping `git diff --unified=0 <base>...<head>` via `subprocess.run`
  - [x] Parse unified diff hunk headers (`@@ -old_start,old_count +new_start,new_count @@`) to calculate 1-based head line numbers
  - [x] Build exclusion filters ignoring binary assets, lockfiles (`package-lock.json`, `poetry.lock`), `.venv/`, and `node_modules/`
  - [x] Populate `DiffFile` models mapping `{ "file_path": {set_of_added_line_numbers} }`
  - [x] Add offline diff parsing fallback accepting raw diff strings or patches for testing
* **Verification Gate:**
  - [x] Unit tests in `tests/test_diff_parser.py` verify exact line mapping on single-line, multi-line, and multi-hunk diffs
  - [x] Diff parsing benchmark completes in $< 250\text{ ms}$ for changes spanning up to 20 files (measured at ~4 ms in tests, 65 ms live)

---

## 3. Phase 2: Core Hybrid Security Detection Engines

### **M3: Hybrid Secret Scanner (Compiled Regex + Shannon Entropy)**
**Goal:** Intercept hardcoded cloud keys and unstructured API tokens with 0% leak rate and $< 350\text{ ms}$ latency.
* **Status:** ✅ Completed
* **Sub-tasks:**
  - [x] Implement compiled regex rules in `src/secret_scanner.py`:
    - [x] `SEC-001`: AWS Access Key ID (`AKIA[0-9A-Z]{16}`) — `CRITICAL`
    - [x] `SEC-002`: AWS Secret Access Key assignment — `CRITICAL`
    - [x] `SEC-003`: GitHub PAT (`ghp_[A-Za-z0-9]{36}`, `github_pat_[A-Za-z0-9_]{82}`) — `CRITICAL`
    - [x] `SEC-004`: Private Cryptographic Keys (`BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY`) — `CRITICAL`
    - [x] `SEC-005`: JSON Web Tokens (`eyJ[A-Za-z0-9_-]{10,}\...`) — `HIGH`
    - [x] `SEC-006`: Slack Webhook / Bot Tokens (`xox[baprs]-[0-9a-zA-Z]{10,48}`) — `HIGH`
  - [x] Implement Shannon entropy calculator: $H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$
  - [x] Enforce entropy gate: candidate strings $\ge 20$ chars with $H(X) > 4.5\text{ bits/char}$ emit `SEC-007` (`HIGH`)
  - [x] Implement suppression allowlist: ignore UUIDs, hex hashes, URL/file paths, regex syntax, and dummy strings (`EXAMPLE`, `TEST`)
  - [x] Implement `redact_secret()` helper masking raw secrets (`AKIA************7X9Q`)
* **Verification Gate:**
  - [x] `tests/test_secret_scanner.py` validates 100% detection on synthetic AWS, GitHub, and high-entropy secret fixtures
  - [x] Confirmed zero unmasked secrets leaked in emitted `Finding.snippet` objects

---

### **M4: Python AST Static Analyzer (Dangerous Execution Sinks)**
**Goal:** Parse Python ASTs to detect command execution, insecure deserialization, and dangerous sinks without comment noise.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Implement `src/ast_analyzer.py` subclassing `ast.NodeVisitor`
  - [ ] Add safe file loading with `SyntaxError` exception handling for partially formed diffs
  - [ ] Implement `visit_Call` rules:
    - [ ] `AST-001`: Code execution sinks (`eval()`, `exec()`, `compile()`) — `CRITICAL`
    - [ ] `AST-002`: Insecure deserialization (`pickle.loads()`, `yaml.load()` without `SafeLoader`) — `CRITICAL`
    - [ ] `AST-003`: Command injection (`subprocess` with `shell=True`, `os.system()`, `os.popen()`) — `HIGH`
    - [ ] `AST-006`: Insecure cryptographic hashing (`hashlib.md5()`, `hashlib.sha1()`) — `MEDIUM`
  - [ ] Implement `visit_Assign` rule:
    - [ ] `AST-005`: Hardcoded credential assignment to sensitive variable names — `HIGH`
  - [ ] Intersect visitor node line numbers (`node.lineno`) with `DiffFile.added_lines` so only PR additions trigger findings
* **Verification Gate:**
  - [ ] `tests/test_ast_analyzer.py` confirms `eval()` inside docstrings or comments produces zero alerts
  - [ ] AST parsing across 10 modified Python files completes in $< 450\text{ ms}$

---

### **M5: AST OWASP SQL Injection & Taint Pattern Detector**
**Goal:** Eliminate SQL injection false alarms on comments/parameterized queries, delivering $\ge 74\%$ false-positive reduction.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Detect database execution calls (`cursor.execute()`, `session.execute()`, `raw()`) in `ast_analyzer.py`
  - [ ] Flag query argument construction if built dynamically using:
    - [ ] f-strings (`ast.JoinedStr`) containing SQL statements — `AST-004` (`CRITICAL`)
    - [ ] String concatenation (`ast.BinOp` with `ast.Add`) — `AST-004` (`CRITICAL`)
    - [ ] Modulo string formatting (`ast.BinOp` with `ast.Mod`) — `AST-004` (`CRITICAL`)
    - [ ] Format calls (`ast.Call` where `func.attr == "format"`) — `AST-004` (`CRITICAL`)
  - [ ] Build safe pass logic: confirm parameterized queries (e.g., `execute("SELECT ... %s", (val,))`) pass cleanly
  - [ ] Attach copy-pasteable remediation snippets (parameterized tuples) to every `AST-004` finding
* **Verification Gate:**
  - [ ] Side-by-side script comparing AST vs. Regex on 50 SQL code/comment samples demonstrates $\ge 74\%$ fewer false alerts
  - [ ] True-positive detection on vulnerable query constructions validates at $\ge 96.4\%$

---

### **M6: Dependency Manifest Parser & OSV.dev Batch CVE Engine**
**Goal:** Audit `requirements.txt` and `package.json` against the OSV.dev database in $< 650\text{ ms}$ via single batch HTTP query.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Implement `src/dep_scanner.py` parsing pinned packages from `requirements.txt` (PyPI) and `package.json` (npm)
  - [ ] Build batch request payload hitting `POST https://api.osv.dev/v1/querybatch`
  - [ ] Configure `requests.Session` with a strict `timeout=3.0` seconds and connection reuse
  - [ ] Parse batch response: extract CVE/GHSA IDs, severity ratings, and minimum patched versions
  - [ ] Map vulnerability findings to the exact physical manifest line number
  - [ ] Wrap external HTTP calls with defensive `RequestException` fallbacks (graceful non-fatal logging)
* **Verification Gate:**
  - [ ] `tests/test_dep_scanner.py` using mocked responses confirms correct hydration of CVE findings
  - [ ] Live batch API call against a 20-package manifest executes in $< 650\text{ ms}$

---

## 4. Phase 3: Aggregation, Policy Gate & GitHub Actions CI

### **M7: Aggregation Engine, Severity Classifier & Policy Gate**
**Goal:** Deduplicate scanner outputs, sort by severity hierarchy, compute latency, and enforce CI merge-blocking exit codes.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Implement `src/aggregator.py` orchestrating Diff Parser $\rightarrow$ Scanners (Secrets, AST, Dependencies)
  - [ ] Deduplicate findings by key `(file_path, line_number, rule_id)`
  - [ ] Sort consolidated findings: `CRITICAL` $\rightarrow$ `HIGH` $\rightarrow$ `MEDIUM`
  - [ ] Compute overall `scan_duration_ms` and populate final `AuditReport` model
  - [ ] Enforce CI exit code policy:
    - [ ] If `critical_count + high_count > 0`: return `sys.exit(1)` (Block PR merge)
    - [ ] If only `medium_count > 0` or clean: return `sys.exit(0)` (Allow PR merge)
* **Verification Gate:**
  - [ ] `tests/test_aggregator.py` confirms exit code `1` on CRITICAL/HIGH findings and exit code `0` on clean scans
  - [ ] Total memory footprint of `AuditReport` aggregation remains $< 50\text{ MB}$

---

### **M8: Automated GitHub PR Review Commenter (REST API)**
**Goal:** Format and upsert idempotent Markdown security audit reports directly onto GitHub Pull Requests.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Implement Markdown report builder in `src/pr_commenter.py` conforming strictly to `DESIGN.md`:
    - [ ] Line 1 hidden idempotency tag: `<!-- security-audit-bot-v1 -->`
    - [ ] Status banner (`❌ Merge Blocked` vs `✅ Passed`) and timing summary table
    - [ ] Findings summary table (`Severity`, `Rule ID`, `Location`, `Description`, `Suggested Fix`)
    - [ ] Collapsible `<details>` blocks containing vulnerable snippets and safe remediation code
  - [ ] Implement GitHub REST API client using standard `requests` and `GITHUB_TOKEN`:
    - [ ] Query existing PR comments via `GET /repos/{owner}/{repo}/issues/{pr}/comments`
    - [ ] If marker found: update comment via `PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}`
    - [ ] If marker absent: post new comment via `POST /repos/{owner}/{repo}/issues/{pr}/comments`
  - [ ] Implement `--dry-run` console ANSI renderer for local execution without GitHub credentials
* **Verification Gate:**
  - [ ] Dry-run prints fully formatted Markdown and ANSI tables to stdout
  - [ ] Simulated 3-commit sequence verifies existing PR comment is updated rather than generating duplicate comments

---

### **M9: Dockerization & Zero-Config GitHub Actions Workflow**
**Goal:** Package the scanner into an isolated container and a drop-in workflow running in $< 4.8\text{s}$ per PR.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Write multi-stage `Dockerfile` based on `python:3.11-slim`
  - [ ] Configure non-root system user (`uid: 1001`, `appuser`) with read-only root filesystem
  - [ ] Create `action.yml` defining action metadata, inputs, and container entrypoint
  - [ ] Create `.github/workflows/security-audit.yml`:
    - [ ] Trigger on `pull_request: [opened, synchronize, reopened]`
    - [ ] Set minimal permissions: `contents: read`, `pull-requests: write`
    - [ ] Run containerized action with environment parameters
* **Verification Gate:**
  - [ ] Docker container build succeeds with an image size $< 180\text{ MB}$
  - [ ] GitHub Actions run on test PR completes end-to-end execution in $< 4.8\text{ seconds}$

---

## 5. Phase 4: Benchmarking, Automated Testing & Multi-Repo Deployment

### **M10: Pytest Verification Suite & Benchmark Dataset (500+ Test Cases)**
**Goal:** Formally verify test coverage ($\ge 85\%$) and validate the exact CV claims (96.4% TPR, 74% FP drop, 0% leak rate).
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Construct synthetic evaluation corpus in `benchmarks/corpus.py` (500+ test cases covering safe/vulnerable patterns)
  - [ ] Implement `benchmarks/run_benchmark.py`:
    - [ ] Execute Regex-only scanner baseline vs. Hybrid AST + Entropy scanner
    - [ ] Calculate confusion matrix: True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN)
    - [ ] Print formal metrics: TPR, Precision, Recall, False-Positive Reduction percentage
  - [ ] Complete offline unit and integration test suite under `tests/` with mocked APIs
  - [ ] Configure code coverage enforcement via `pytest --cov=src --cov-fail-under=85`
* **Verification Gate:**
  - [ ] Benchmark verifies: AST TPR $\ge 96.4\%$, FP reduction $\ge 74\%$, and Secret leakage $= 0\%$
  - [ ] Full test suite executes in $< 10\text{ seconds}$ with $\ge 85\%$ test coverage

---

### **M11: Multi-Repo Deployment & Portfolio Documentation**
**Goal:** Deploy the audit bot across 3+ real GitHub repositories, capture PR artifacts, and publish documentation.
* **Status:** ⬜ Pending
* **Sub-tasks:**
  - [ ] Deploy `.github/workflows/security-audit.yml` into 3 separate GitHub repositories
  - [ ] Open sample PRs containing deliberate test vulnerabilities (dummy AWS key, `eval()` sink, vulnerable manifest)
  - [ ] Verify automated line-level comment posting and merge-check failure
  - [ ] Capture high-resolution screenshots of PR comments, blocked checks, and terminal benchmark tables
  - [ ] Author portfolio-ready `README.md` featuring architecture diagrams, benchmark results, and setup instructions
* **Verification Gate:**
  - [ ] 3 live GitHub pull requests successfully audited and documented with screenshots
  - [ ] Repository is 100% clean, reproducible, and ready for portfolio presentation and interview defense

---

## 6. Milestone Completion Log

| Milestone ID | Date Completed | Verified By | Git Commit SHA | Key Artifact / Deliverable |
| :--- | :---: | :---: | :---: | :--- |
| **M1: Baseline** | 2026-10-24 | Automated Pytest & Ruff | `d3becf4` | `pyproject.toml`, `models.py`, `main.py`, test suite (98% cov) |
| **M2: Git Diff** | 2026-10-24 | Automated Pytest & Diff Benchmark | `295f869` | `diff_parser.py`, 16 unit tests, live git diff integration |
| **M3: Secrets** | 2026-10-24 | Automated Pytest & Synthetic Fixtures | `8bf644b` | `secret_scanner.py`, 23 secret tests, 0% leak rate |
| **M4: AST Sinks** | — | — | — | `ast_analyzer.py`, sink visitor |
| **M5: SQLi AST** | — | — | — | SQL injection visitor, benchmark script |
| **M6: OSV Batch** | — | — | — | `dep_scanner.py`, OSV batch integration |
| **M7: Policy Gate**| — | — | — | `aggregator.py`, exit code policy logic |
| **M8: Commenter** | — | — | — | `pr_commenter.py`, idempotent upsert |
| **M9: Docker/CI** | — | — | — | `Dockerfile`, `action.yml`, workflow |
| **M10: Pytest** | — | — | — | `run_benchmark.py`, 85%+ test coverage |
| **M11: Deploy** | — | — | — | 3 active repos, portfolio `README.md` |