# ARCHITECTURE.md — Automated GitHub PR Security Audit Bot

## 1. System Overview & Architectural Philosophy
The **Automated GitHub PR Security Audit Bot** is a stateless, zero-database, containerized static security analysis engine developed in **Python 3.11+**. It operates directly within **GitHub Actions** CI/CD workflows on `pull_request` events (`opened`, `synchronize`, `reopened`).

### 1.1 Core Principles
1. **Diff-Scoped Analysis (Targeted Execution):** Rather than scanning an entire repository—which introduces prohibitive CI execution overhead and historical alert fatigue—the engine analyzes strictly the modified lines (`+` lines) extracted from the unified git diff (`git diff --unified=0 <base>...<head>`).
2. **Stateless Operations (Zero External Database):** The bot requires no backing store (no PostgreSQL, SQLite, or Redis). Comment deduplication and state tracking are handled directly in the GitHub Pull Request comment thread using an invisible HTML idempotency marker (`<!-- security-audit-bot-v1 -->`).
3. **Tri-Engine Scanning Pipeline:**
   - **Engine 1 (Hybrid Secret Scanner):** Compiled regex patterns paired with a Shannon Entropy calculator ($H(X) > 4.5\text{ bits/char}$ on strings $\ge 20$ chars) to prevent credential leakage.
   - **Engine 2 (AST Static Security Analyzer):** Python `ast.NodeVisitor` tree traversal inspecting actual syntactic execution sinks (OWASP Top-10) to cut false positives by $\ge 74\%$ compared to regex matching.
   - **Engine 3 (OSV.dev Batch Dependency Auditor):** Single HTTP `POST /v1/querybatch` request auditing dependencies against open-source vulnerability databases in $< 650\text{ ms}$.
4. **Deterministic Hard Performance SLA:** End-to-end execution completes in $< 4.8\text{ seconds}$ per Pull Request under normal CI container conditions.

---

## 2. Tech Stack & Dependency Rules

| Component | Tool / Library | Version Pinning | Architectural Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime** | Python | `3.11-slim` | Core engine runtime; utilizes native `ast`, `re`, `math`, `subprocess`, `sys`, and `json`. |
| **Data Validation** | `pydantic` | `>=2.6.0,<3.0.0` | Enforces type safety, strict schema serialization, and validation across module boundaries. |
| **HTTP Transport** | `requests` | `>=2.31.0,<3.0.0` | Synchronous network client for OSV.dev batch API and GitHub REST API v3 comment upsert. |
| **Testing Engine** | `pytest` | `>=8.0.0` | Automated test suite and confusion-matrix benchmark verification. |
| **Coverage Tool** | `pytest-cov` | `>=5.0.0` | Code coverage enforcement ($\ge 85\%$ threshold). |
| **Linter / Formatter**| `ruff` | `>=0.3.0` | High-speed static linting and PEP 8 formatting validation. |
| **Container Engine** | Docker | `24.0+` | Multi-stage, non-root execution container (`uid 1001`). |
| **CI Automation** | GitHub Actions | `v4` | Event trigger and workflow orchestration layer. |

> **Anti-Bloat Directive:** Do NOT install `aiohttp`, `httpx`, `sqlalchemy`, `celery`, `redis`, `bandit`, `semgrep`, `trufflehog`, `langchain`, or `openai`. All scanning logic must be implemented natively from first principles.

---

## 3. Directory Layout

```text
github-pr-security-bot/
├── .github/
│   └── workflows/
│       └── security-audit.yml       # Production GitHub Actions workflow definition
├── src/
│   ├── __init__.py
│   ├── models.py                    # Pydantic data schemas (Finding, Severity, DiffFile, AuditReport)
│   ├── config.py                    # Regex patterns, entropy thresholds, allowlists, rule definitions
│   ├── diff_parser.py               # Subprocess git diff parser and added-line mapper
│   ├── secret_scanner.py            # Compiled Regex + Shannon Entropy hybrid engine
│   ├── ast_analyzer.py              # Python ast.NodeVisitor for OWASP sinks & SQL injection
│   ├── dep_scanner.py               # Manifest parser (requirements.txt, package.json) & OSV batch client
│   ├── aggregator.py                # Finding deduplication, sorting, and CI policy exit-code gate
│   ├── pr_commenter.py              # Markdown table formatter & GitHub REST API comment upsert
│   └── main.py                      # CLI entrypoint orchestrating pipeline execution (< 4.8s budget)
├── benchmarks/
│   ├── __init__.py
│   ├── corpus.py                    # 500+ synthetic commit fixtures (vulnerable vs. benign test cases)
│   └── run_benchmark.py             # Generates confusion matrix (proves 96.4% TPR & 74% FP reduction)
├── tests/
│   ├── __init__.py
│   ├── test_diff_parser.py
│   ├── test_secret_scanner.py
│   ├── test_ast_analyzer.py
│   ├── test_dep_scanner.py
│   ├── test_aggregator.py
│   └── test_pr_commenter.py
├── trackers/                        # Phase and milestone status tracking files
├── PRD.md                           # Product Requirements Document
├── ARCHITECTURE.md                  # System Architecture Specification
├── DESIGN.md                        # Markdown UI and layout guidelines
├── MEMORY.md                        # Session state and progress tracking
├── RULES.md                         # Engineering rules and coding constraints
├── TRACKER.md                       # Master milestone progress tracker
├── Dockerfile                       # python:3.11-slim container definition
├── action.yml                       # Composite / Docker GitHub Action metadata
├── requirements.txt                 # Pinned application dependencies
└── pyproject.toml                   # Project metadata, pytest, and ruff configurations
```

---

## 4. Domain Data Models (`src/models.py`)

All communication between internal modules is strictly enforced through Pydantic v2 schemas. Passing untyped dictionaries across module boundaries is prohibited.

```python
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"

class ScannerCategory(str, Enum):
    SECRET = "SECRET"
    AST_OWASP = "AST_OWASP"
    DEPENDENCY_CVE = "DEPENDENCY_CVE"

class DiffFile(BaseModel):
    file_path: str
    added_lines: Dict[int, str] = Field(
        default_factory=dict,
        description="Map of physical 1-based line_number -> raw added line string for '+' lines"
    )

class Finding(BaseModel):
    file_path: str
    line_number: int = Field(ge=1)
    rule_id: str = Field(description="e.g., SEC-001, AST-004, DEP-OSV")
    category: ScannerCategory
    severity: Severity
    title: str
    description: str
    remediation: str
    snippet: Optional[str] = Field(
        default=None,
        description="Redacted snippet; raw secrets must be masked with redact_secret()"
    )

class AuditReport(BaseModel):
    repository: str
    pr_number: Optional[int] = None
    base_sha: str
    head_sha: str
    scan_duration_ms: float
    dep_scan_duration_ms: float = 0.0
    files_scanned: int
    findings: List[Finding] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def should_block_merge(self) -> bool:
        return (self.critical_count + self.high_count) > 0
```

---

## 5. End-to-End Pipeline & Execution Flow

```text
[GitHub PR Event: opened / synchronize]
                   │
                   ▼
┌──────────────────────────────────────────────────────────┐
│ 1. CLI Entrypoint (src/main.py)                          │
│    Parses: --base, --head, --repo, --pr-number, --dry-run │
└──────────────────┬───────────────────────────────────────┘
                   │
                   ▼  (< 300 ms)
┌──────────────────────────────────────────────────────────┐
│ 2. Git Diff Parser (src/diff_parser.py)                  │
│    Executes: git diff --unified=0 <base>...<head>        │
│    Extracts modified files & physical '+' line numbers   │
│    Filters: lockfiles, binaries, fixtures, .venv/        │
└──────────────────┬───────────────────────────────────────┘
                   │ Returns: List[DiffFile]
         ┌─────────┴───────────────────────┬─────────────────────────┐
         ▼ (< 800 ms)                      ▼ (< 1,200 ms)            ▼ (< 650 ms)
┌──────────────────────────┐ ┌──────────────────────────┐ ┌──────────────────────────┐
│ 3A. Secret Scanner       │ │ 3B. AST Static Analyzer  │ │ 3C. OSV Dep Scanner      │
│ (src/secret_scanner.py)  │ │ (src/ast_analyzer.py)    │ │ (src/dep_scanner.py)     │
│ - Scans '+' lines only   │ │ - Parses modified .py    │ │ - Parses package.json &  │
│ - Compiled Regex check   │ │   files via ast.parse()  │ │   requirements.txt       │
│ - Shannon Entropy > 4.5  │ │ - Intersects AST nodes   │ │ - Single Batch POST to   │
│   on literals >= 20 char │ │   with '+' line numbers  │ │   api.osv.dev/v1/        │
│ - Masks secrets in output│ │ - Flags OWASP sinks/SQLi │ │   querybatch             │
└────────┬─────────────────┘ └─────────────┬────────────┘ └────────────┬─────────────┘
         │                                 │                           │
         └─────────────────────────────────┼───────────────────────────┘
                                           ▼ (< 100 ms)
┌──────────────────────────────────────────────────────────┐
│ 4. Aggregator & Policy Gate (src/aggregator.py)          │
│    Deduplicates by (file_path, line_number, rule_id)     │
│    Sorts: CRITICAL -> HIGH -> MEDIUM                     │
│    Calculates scan_duration_ms & should_block_merge      │
└──────────────────┬───────────────────────────────────────┘
                   │ Returns: AuditReport
                   ▼ (< 900 ms)
┌──────────────────────────────────────────────────────────┐
│ 5. PR Commenter (src/pr_commenter.py)                    │
│    Builds Markdown table report (per DESIGN.md)          │
│    Upserts comment via GitHub REST API (<!-- marker -->) │
│    Exits with sys.exit(1) if CRITICAL/HIGH > 0 else 0    │
└──────────────────────────────────────────────────────────┘
```

### Execution Time Budget Allocation
* **Diff Parsing:** $< 300\text{ ms}$
* **Secret Scanning (Regex + Entropy):** $< 800\text{ ms}$
* **AST Static Analysis:** $< 1,200\text{ ms}$
* **OSV.dev Batch CVE Lookup:** $< 650\text{ ms}$
* **Aggregation & Report Formatting:** $< 100\text{ ms}$
* **GitHub Comment Upsert (REST API):** $< 900\text{ ms}$
* **Total SLA Budget:** $< 4,800\text{ ms}\ (4.8\text{ seconds})$

---

## 6. Detailed Subsystem Specifications

### 6.1 Git Diff Parser (`src/diff_parser.py`)
- **Git Execution:**
  ```bash
  git diff --unified=0 <base_sha>...<head_sha>
  ```
- **Hunk Parsing Algorithm:**
  Matches unified diff hunk headers using the regex:
  ```regex
  ^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@
  ```
  - Group 1 represents the starting line in the head file (`current_line`).
  - For each succeeding line:
    - If the line begins with `+` (and is not a file header `+++ b/...`), record `added_lines[current_line] = line[1:]` and increment `current_line` by 1.
    - If the line begins with `-`, do not increment `current_line`.
    - If the line begins with ` ` (context), increment `current_line` by 1.
- **Path Exclusion Rules:**
  Skip file paths matching:
  - Binaries / assets: `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`, `.pdf`, `.zip`, `.gz`
  - Lockfiles: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`
  - Ignored directories: `node_modules/`, `.venv/`, `venv/`, `dist/`, `build/`, `.git/`

---

### 6.2 Hybrid Secret Scanner (`src/secret_scanner.py`)
Processes every added line from `DiffFile.added_lines`.

#### Tier 1: Compiled Regular Expression Engine
```python
RULES = {
    "SEC-001": {
        "title": "Exposed AWS Access Key ID",
        "pattern": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": Severity.CRITICAL,
    },
    "SEC-002": {
        "title": "Potential AWS Secret Access Key",
        "pattern": re.compile(r"(?i)aws_?(?:secret)?_?(?:access)?_?key.*?['\"]([A-Za-z0-9/+=]{40})['\"]"),
        "severity": Severity.CRITICAL,
    },
    "SEC-003": {
        "title": "Exposed GitHub Personal Access Token",
        "pattern": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}"),
        "severity": Severity.CRITICAL,
    },
    "SEC-004": {
        "title": "Private Cryptographic Key Header",
        "pattern": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----"),
        "severity": Severity.CRITICAL,
    },
    "SEC-005": {
        "title": "Exposed JSON Web Token (JWT)",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": Severity.HIGH,
    },
    "SEC-006": {
        "title": "Exposed Slack Token or Webhook",
        "pattern": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "severity": Severity.HIGH,
    },
}
```

#### Tier 2: Shannon Entropy Engine (`SEC-007`)
Evaluates string literals of length $\ge 20$ characters that do not contain whitespace:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Where:
- $n$ is the number of distinct characters in the string candidate $X$.
- $P(x_i) = \frac{\text{count}(x_i)}{\text{length}(X)}$ is the probability of character $x_i$ occurring.

If $H(X) > 4.5\text{ bits/char}$ and the candidate is not in the allowlist, emit `SEC-007` (`Severity.HIGH`).

#### Tier 3: Suppression Allowlist
Ignore candidates that match:
- Standard UUIDs: `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
- File system paths or URLs: contains `/`, `\\`, or starts with `http://` / `https://`
- Hex color strings: `^#[0-9a-fA-F]{6}$`
- Dummy / sample placeholders: contains `EXAMPLE`, `DUMMY`, `TEST`, `PLACEHOLDER`, `YOUR_KEY_HERE`, `CHANGEME`

#### Secret Redaction Function
```python
def redact_secret(raw_secret: str) -> str:
    if len(raw_secret) <= 8:
        return "********"
    return f"{raw_secret[:4]}{'*' * 12}{raw_secret[-4:]}"
```

---

### 6.3 Python AST Static Analyzer (`src/ast_analyzer.py`)
Processes modified files ending in `.py`.

1. **Full-File AST Generation:**
   Reads the entire Python source file from disk and parses it using `ast.parse(source, filename=path)` to ensure valid syntactic context.
2. **Diff Intersection:**
   The custom visitor inherits from `ast.NodeVisitor` and receives `added_lines: Set[int]`.
   Findings are recorded **if and only if** `node.lineno in added_lines`.
3. **Detection Rules:**
   - `AST-001` (**Dangerous Execution Sink** — `CRITICAL`): Calls to `eval()`, `exec()`, or `compile()`.
   - `AST-002` (**Insecure Deserialization** — `CRITICAL`): Calls to `pickle.loads()`, `pickle.load()`, `_pickle.loads()`, or `yaml.load()` lacking `Loader=yaml.SafeLoader`.
   - `AST-003` (**Command Injection / Insecure Shell** — `HIGH`): Calls to `os.system()`, `os.popen()`, or `subprocess.run()`, `Popen()`, `call()`, `check_output()` where keyword argument `shell=True`.
   - `AST-004` (**OWASP SQL Injection Sink** — `CRITICAL`):
     - Triggered when method call name is `execute`, `executemany`, or `raw`.
     - First positional argument (`node.args[0]`) is dynamically constructed:
       - `ast.JoinedStr` (f-string)
       - `ast.BinOp` with `op=ast.Add()` (string concatenation)
       - `ast.BinOp` with `op=ast.Mod()` (`%` formatting)
       - `ast.Call` where `func.attr == "format"`
     - Must contain one or more SQL keywords: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `WHERE`.
     - *Safe Pattern Handling:* Parameterized statements passing queries as static string constants alongside parameter tuples (e.g., `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`) evaluate to `ast.Constant` and are **never** flagged.
   - `AST-005` (**Hardcoded Sensitive Credential** — `HIGH`): Variable assignments (`ast.Assign`, `ast.AnnAssign`) where target name matches `(?i)(password|passwd|secret|api_key|access_token|private_key)` and assigned value is a non-empty `ast.Constant` string. Calls to `os.getenv()` or `os.environ.get()` are ignored.
   - `AST-006` (**Weak Cryptographic Hash** — `MEDIUM`): Calls to `hashlib.md5()` or `hashlib.sha1()` without `usedforsecurity=False`.

---

### 6.4 Batch Dependency CVE Scanner (`src/dep_scanner.py`)
Triggered when `requirements.txt` or `package.json` appears in the diff.

1. **Manifest Extraction:**
   - `requirements.txt`: Matches pinned versions `^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)` (`PyPI` ecosystem).
   - `package.json`: Parses `"dependencies"` and `"devDependencies"` JSON objects, stripping `^` and `~` prefixes (`npm` ecosystem).
2. **OSV.dev Batch Request Protocol:**
   - **Endpoint:** `POST https://api.osv.dev/v1/querybatch`
   - **Timeout:** Strict 3.0-second limit.
   - **Payload Schema:**
     ```json
     {
       "queries": [
         {
           "package": { "name": "requests", "ecosystem": "PyPI" },
           "version": "2.19.0"
         },
         {
           "package": { "name": "lodash", "ecosystem": "npm" },
           "version": "4.17.15"
         }
       ]
     }
     ```
3. **Vulnerability Mapping & Normalization:**
   - Inspects `results[i].vulns`.
   - Extracts vulnerability identifier (`GHSA-...` or `CVE-...`), summary, and database-specific CVSS score.
   - Severity classification:
     - CVSS $\ge 9.0$ $\rightarrow$ `CRITICAL`
     - CVSS $7.0\text{–}8.9$ $\rightarrow$ `HIGH`
     - CVSS $< 7.0$ $\rightarrow$ `MEDIUM`
   - Extracts the minimum fixed version string from `affected[].ranges[].events[].fixed`.
   - Links the finding directly to the line number in the manifest where the package was pinned.

---

### 6.5 PR Review Commenter (`src/pr_commenter.py`)
Interacts with the GitHub Issues/PR Comments REST API v3 using the runner's `GITHUB_TOKEN`.

- **Headers:**
  ```text
  Authorization: Bearer <GITHUB_TOKEN>
  Accept: application/vnd.github+json
  X-GitHub-Api-Version: 2022-11-28
  ```
- **Idempotency Logic:**
  1. Executes `GET https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments?per_page=100`.
  2. Scans comment bodies for the hidden string: `<!-- security-audit-bot-v1 -->`.
  3. **If found:** Updates existing comment via `PATCH https://api.github.com/repos/{owner}/{repo}/issues/comments/{comment_id}`.
  4. **If not found:** Creates new comment via `POST https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments`.
- **Merge Blocking Policy Gate:**
  ```python
  if report.should_block_merge:
      sys.exit(1)
  else:
      sys.exit(0)
  ```

---

## 7. Error Handling, Fault Tolerance & Edge Cases

| Failure Scenario | Fallback & Recovery Mechanism |
| :--- | :--- |
| **Python Syntax Error in PR** | If a modified `.py` file contains broken syntax, `ast_analyzer.py` catches `SyntaxError`, logs a warning to `stderr` with file path and line number, and continues scanning remaining files without terminating. |
| **OSV.dev Network Timeout / Outage** | Network calls to `api.osv.dev` use a 3.0s timeout. If `requests.RequestException` or HTTP 5xx is encountered, the error is logged as a non-fatal warning, returning an empty list so AST and Secret findings are still posted to the PR. |
| **Rate Limit on GitHub API** | Catch HTTP 403 / 429 on comment upsert. If comment posting fails, emit the full Markdown report to container `stdout` / workflow logs and enforce `sys.exit(1)` if critical findings exist. |
| **Missing GITHUB_TOKEN or `--dry-run`** | If `--dry-run` is supplied or `GITHUB_TOKEN` is unset in the environment, bypass all GitHub REST API network calls and print the formatted Markdown report directly to terminal standard output. |
| **Renamed or Deleted Files** | Diff parser verifies physical file existence via `os.path.exists()` before delegating to `ast_analyzer.py` or manifest readers, preventing `FileNotFoundError` on deleted files. |

---

## 8. Docker & GitHub Actions Pipeline Specification

### 8.1 Multi-Stage Container Definition (`Dockerfile`)
```dockerfile
FROM python:3.11-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3.11-slim

WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY src/ /app/src/

ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app

RUN useradd -u 1001 -m botuser && chown -R botuser:botuser /app
USER 1001

ENTRYPOINT ["python", "-m", "src.main"]
```

### 8.2 GitHub Actions Workflow (`.github/workflows/security-audit.yml`)
```yaml
name: Security Audit Bot

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Security Audit Bot
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPO_NAME: ${{ github.repository }}
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          python3 -m pip install -r requirements.txt
          python3 -m src.main \
            --base "$BASE_SHA" \
            --head "$HEAD_SHA" \
            --repo "$REPO_NAME" \
            --pr-number "$PR_NUMBER"
```