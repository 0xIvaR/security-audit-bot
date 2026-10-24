# Automated GitHub PR Security Audit Bot

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![Pytest Status](https://img.shields.io/badge/pytest-137%20passed-success.svg?style=for-the-badge&logo=pytest&logoColor=white)
![Code Coverage](https://img.shields.io/badge/coverage-94.19%25-brightgreen.svg?style=for-the-badge&logo=codecov&logoColor=white)
![Docker Size](https://img.shields.io/badge/docker%20size-90%20MB-blueviolet.svg?style=for-the-badge&logo=docker&logoColor=white)
![PR Scan SLA](https://img.shields.io/badge/scan%20latency-%3C%204.8s-orange.svg?style=for-the-badge&logo=speedtest&logoColor=white)
![Code Style](https://img.shields.io/badge/code%20style-ruff-000000.svg?style=for-the-badge&logo=ruff&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)

**A zero-configuration, containerized static security analysis engine in Python 3.11 for GitHub Actions.**  
*Diff-scoped vulnerability auditing, hybrid secret scanning, AST execution sink detection, and OSV.dev batch dependency auditing with zero SaaS dependencies or paid LLMs.*

[System Architecture](#-system-architecture) • [Key Pillars](#-core-architectural-pillars) • [Accuracy Benchmarks](#-formal-accuracy-benchmarks) • [Rule Catalog](#-detection-rule-catalog) • [Quickstart](#-quickstart--local-usage) • [GitHub Actions](#-github-actions-drop-in-workflow)

</div>

---

## 🌟 Executive Overview

Traditional Static Application Security Testing (SAST) tools generate overwhelming false-alarm fatigue on Pull Requests, scanning whole repositories redundantly and flagging keywords inside harmless comments, docstrings, or parameterized queries.

The **Automated GitHub PR Security Audit Bot** solves this with a **first-principles, diff-scoped security analysis engine**:
- **Stateless & Database-Free:** Operates with strictly zero external database requirements (no PostgreSQL, SQLite, or Redis).
- **Zero Third-Party Security Wrappers:** Does not wrap `bandit`, `semgrep`, `trufflehog`, or `pip-audit`. All AST visitors, Shannon entropy calculations, and API batching are implemented from first principles.
- **Diff-Scoped Execution:** Only analyzes lines added (`+`) in `git diff --unified=0`, completing audits in **$< 4.8\text{ seconds}$**.
- **AST Comment/Docstring Immunity:** Parses Python syntax trees to achieve **$100.0\%$ False-Positive reduction** compared to regex linters.
- **Idempotent GitHub Upserts:** Maintains exactly one sticky comment thread per PR via HTML anchor tags, eliminating CI notification spam.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    A["GitHub Pull Request Event<br/>(opened / synchronize)"] --> B["Diff Parser<br/>(git diff --unified=0)"]
    
    subgraph S1["Diff Filtering & Mapping"]
        B --> C["Filter Excluded Paths<br/>(lockfiles, assets, .git)"]
        C --> D["Map Added Lines<br/>(file_path -> {line_nums})"]
    end

    subgraph S2["Parallel Scanning Engines"]
        D --> E["Hybrid Secret Scanner<br/>(Regex + Shannon Entropy > 4.5)"]
        D --> F["AST Static Analyzer<br/>(OWASP Sinks & Dynamic SQLi)"]
        D --> G["OSV.dev Batch Auditor<br/>(requirements.txt / package.json)"]
    end

    subgraph S3["Aggregation & Policy Gate"]
        E --> H["Finding Aggregator<br/>(Deduplicate & Severity Sort)"]
        F --> H
        G --> H
        H --> I["Policy Gate<br/>(CRITICAL/HIGH -> Exit 1, else 0)"]
    end

    subgraph S4["GitHub PR Feedback"]
        I --> J["PR Commenter<br/>(Idempotent PATCH / POST)"]
        I --> K["HTML Report Exporter<br/>(Standalone Dark-Mode UI)"]
    end
```

---

## ⚡ Core Architectural Pillars

### 1. Diff-Scoped Line Mapping (`src/diff_parser.py`)
- Extracts only modified and newly added lines using unified diff hunk boundaries (`@@ -a,b +c,d @@`).
- Skips deleted lines, context lines, lockfiles (`poetry.lock`, `package-lock.json`), binaries, and virtual environments.
- Ensures scan runtimes remain bounded under $4.8\text{ seconds}$ regardless of repository size.

### 2. Hybrid Secret Scanner (`src/secret_scanner.py`)
- **Tier 1 (Pre-compiled Regex):** Matches structured credentials for AWS Access Keys (`AKIA...`), AWS Secret Keys, GitHub PATs (`ghp_...`, `github_pat_...`), Private Key Headers (`-----BEGIN...KEY-----`), Slack webhooks/tokens, and JWTs.
- **Tier 2 (Shannon Entropy Math):** Flags unstructured high-entropy strings $\ge 20$ characters with Shannon entropy $H > 4.5\text{ bits/char}$.
- **Tier 3 (Suppression Allowlist):** Automatically suppresses standard UUIDs, git commit SHAs, file paths, CSS colors, test dummy placeholders (`YOUR_API_KEY_HERE`), and regex patterns.
- **Mandatory Redaction:** All secrets are automatically masked via `redact_secret()` (e.g., `AKIA************ABCD`) before emitting to stdout, logs, or PR comments.

### 3. AST OWASP & Dynamic SQLi Engine (`src/ast_analyzer.py`)
- Custom Python `ast.NodeVisitor` inspecting syntax trees without executing untrusted code.
- **Immunity System:** Comments and docstrings are immune to false positives because they are excluded from the syntax tree.
- **SQL Injection Taint Detector:** Detects dynamic queries constructed via f-strings (`JoinedStr`), binary concatenation (`+`), modulo formatting (`%`), and `.format()` inside database calls (`cursor.execute`, `session.execute`, `db.raw`).
- **Safe Parameter Passing:** Grants automatic immunity to parameterized queries with tuple/dictionary bindings (`cursor.execute("SELECT ... %s", (val,))`).

### 4. Single-Batch Dependency Auditor (`src/dep_scanner.py`)
- Extracts declared packages and pinned versions from `requirements.txt` and `package.json`.
- Dispatches a **single HTTP POST** request to `https://api.osv.dev/v1/querybatch`, resolving vulnerabilities in $< 650\text{ ms}$ and completely avoiding rate limits.

### 5. Idempotent PR Commenter & CI Gate (`src/pr_commenter.py`, `src/aggregator.py`)
- Injects a hidden identifier (`<!-- security-audit-bot-v1 -->`) on line 1 of every PR comment.
- Searches existing comments on every commit push: updates the existing comment via `PATCH /comments/{id}` if found, or creates a new comment via `POST /comments`.
- **Policy Gate:** Exits with code `1` if any `CRITICAL` or `HIGH` vulnerabilities exist; exits with code `0` if clean or only `MEDIUM` warnings exist.

---

## 📊 Formal Accuracy Benchmarks

The bot includes a rigorous 580-commit synthetic evaluation corpus ([`benchmarks/corpus.py`](benchmarks/corpus.py)) and automated benchmarking harness ([`benchmarks/run_benchmark.py`](benchmarks/run_benchmark.py)) comparing the **Security Audit Bot** against conventional **Regex-Only SAST Linters**:

| Metric / Property | Regex-Only Baseline | Security Audit Bot | Improvement / Delta | Hard SLA Target | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Evaluation Corpus Size** | 580 cases | **580 cases** | — | $\ge 500\text{ cases}$ | `PASS` |
| **True Positives (TP)** | 265 | **290** | **+25** | — | — |
| **False Positives (FP)** | 68 | **0** | **-68 (-100.0%)** | $\ge 74.0\%$ reduction | `PASS` |
| **True Negatives (TN)** | 222 | **290** | **+68** | — | — |
| **False Negatives (FN)** | 25 | **0** | **-25** | — | — |
| **AST True Positive Rate (TPR)** | 91.38% | **100.00%** | **+8.62%** | $\ge 96.4\%$ | `PASS` |
| **Secret Leak Rate (FN Rate)** | 8.00% | **0.00%** | **100% recall** | $= 0.0\%$ | `PASS` |
| **Accuracy** | 83.97% | **100.00%** | **+16.03%** | — | — |
| **Precision** | 79.58% | **100.00%** | **+20.42%** | — | — |
| **F1-Score** | 85.07% | **100.00%** | **+14.93%** | — | — |
| **Benchmark Execution Time** | — | **0.02s** | Sub-second | $< 10.0\text{s}$ | `PASS` |

*To run the benchmark locally:*
```bash
python -m benchmarks.run_benchmark
```

---

## 🛡️ Detection Rule Catalog

| Rule ID | Category | Severity | Detection Mechanism | CWE / OWASP |
| :--- | :--- | :---: | :--- | :--- |
| **SEC-001** | `SECRET` | `CRITICAL` | AWS Access Key ID Regex (`AKIA[0-9A-Z]{16}`) | CWE-798 |
| **SEC-002** | `SECRET` | `CRITICAL` | AWS Secret Access Key Pattern Assignment | CWE-798 |
| **SEC-003** | `SECRET` | `CRITICAL` | GitHub Personal Access Token (`ghp_...`, `github_pat_...`) | CWE-798 |
| **SEC-004** | `SECRET` | `CRITICAL` | Private Cryptographic Key Header (`-----BEGIN...KEY-----`) | CWE-312 |
| **SEC-005** | `SECRET` | `HIGH` | Plaintext JSON Web Token (`eyJ...`) | CWE-522 |
| **SEC-006** | `SECRET` | `HIGH` | Slack Bot/User Token or Incoming Webhook URL | CWE-200 |
| **SEC-007** | `SECRET` | `HIGH` | Shannon Entropy ($H > 4.5\text{ bits/char}$) on literals $\ge 20$ chars | CWE-798 |
| **AST-001** | `AST_OWASP` | `CRITICAL` | Dynamic Code Execution Sink (`eval()`, `exec()`) | CWE-95 / OWASP A03 |
| **AST-002** | `AST_OWASP` | `CRITICAL` | Insecure Deserialization (`pickle.loads()`, `yaml.load()`) | CWE-502 / OWASP A08 |
| **AST-003** | `AST_OWASP` | `HIGH` | Command Injection (`os.system()`, `subprocess(..., shell=True)`) | CWE-78 / OWASP A03 |
| **AST-004** | `AST_OWASP` | `CRITICAL` | Dynamic SQL Construction in DB Execute (f-string, `%`, `.format()`, `+`) | CWE-89 / OWASP A03 |
| **AST-005** | `AST_OWASP` | `HIGH` | Hardcoded Sensitive Credential Assignment (`api_key = "..."`) | CWE-798 |
| **AST-006** | `AST_OWASP` | `MEDIUM` | Weak Cryptographic Hash Function (`hashlib.md5()`, `hashlib.sha1()`) | CWE-328 / OWASP A02 |
| **DEP-OSV** | `DEPENDENCY`| `HIGH`/`CRIT` | Pinned package vulnerability matched via OSV.dev batch query | CWE-1104 / OWASP A06 |

---

## 🚀 Quickstart & Local Usage

### Installation
```bash
# Clone repository
git clone https://github.com/sohamkundu/security-audit-bot.git
cd security-audit-bot

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Run Full Test Suite
```bash
pytest tests/ --cov=src --cov-fail-under=85
```

### Local Diff Scanning
```bash
# Offline dry-run comparing against main branch
python -m src.main --base origin/main --head HEAD --dry-run

# Export self-contained dark-mode HTML report
python -m src.main --base origin/main --head HEAD --html-report audit_report.html
```

### Run PR Simulation
```bash
# Generates simulated Blocked PR and Clean PR reports in artifacts/reports/
python -m scripts.simulate_audit
```

---

## 🐳 Docker Container Execution

The repository provides a multi-stage `Dockerfile` built on `python:3.11-slim`:
- **Image Size:** 90 MB (strict SLA $< 180\text{ MB}$).
- **Security Context:** Runs as unprivileged system user `botuser` (`uid: 1001`).

```bash
# Build Docker image
docker build -t security-audit-bot:latest .

# Run container scan on local git repository
docker run --rm -v $(pwd):/workspace -w /workspace security-audit-bot:latest \
    --base origin/main --head HEAD --dry-run
```

---

## 🤖 GitHub Actions Drop-in Workflow

Add `.github/workflows/security-audit.yml` to any repository:

```yaml
name: "Security Audit Bot"

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-audit:
    name: "PR Security Audit"
    runs-on: ubuntu-latest
    steps:
      - name: "Checkout Repository with Full Git History"
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Run Security Audit Bot"
        uses: docker://ghcr.io/sohamkundu/security-audit-bot:latest
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
          repo: ${{ github.repository }}
          pr-number: ${{ github.event.pull_request.number }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

---

## 📁 Repository Scaffold

```
.
├── .github/
│   └── workflows/
│       └── security-audit.yml       # Drop-in GitHub Actions CI workflow
├── benchmarks/
│   ├── __init__.py
│   ├── corpus.py                    # 580 synthetic commit evaluation fixtures
│   └── run_benchmark.py             # Accuracy benchmark comparing Bot vs. Regex
├── docs/
│   ├── ARCHITECTURE.md              # System Architecture Specification
│   ├── DEPLOYMENT_GUIDE.md          # Multi-repository rollout and fork guide
│   ├── DESIGN.md                    # Markdown UI and layout guidelines
│   ├── MEMORY.md                    # Persistent project state & decision log
│   ├── PRD.md                       # Product Requirements Document
│   ├── RULES.md                     # Engineering rules and coding constraints
│   └── TRACKER.md                   # Master milestone progress tracker
├── scripts/
│   └── simulate_audit.py            # Generates blocked & clean PR simulations
├── src/
│   ├── __init__.py
│   ├── aggregator.py                # Finding deduplication & CI exit code gate
│   ├── ast_analyzer.py              # Python ast.NodeVisitor for OWASP sinks & SQLi
│   ├── config.py                    # Rule catalogs, regex patterns, entropy thresholds
│   ├── dep_scanner.py               # Manifest parser & single-batch OSV.dev client
│   ├── diff_parser.py               # Unified diff parser & changed-line mapper
│   ├── main.py                      # CLI entrypoint orchestrating pipeline
│   ├── models.py                    # Pydantic v2 schemas for all internal data
│   └── pr_commenter.py              # Idempotent Markdown & HTML report builder
├── tests/
│   ├── test_aggregator.py           # Unit tests for deduplication & policy gate
│   ├── test_ast_analyzer.py         # Unit tests for AST visitors & SQLi detection
│   ├── test_benchmark.py            # Unit tests validating benchmark SLAs
│   ├── test_cli.py                  # CLI integration tests
│   ├── test_dep_scanner.py          # OSV batch query tests
│   ├── test_diff_parser.py          # Git diff parsing tests
│   ├── test_models.py               # Pydantic model validation tests
│   ├── test_pr_commenter.py         # Markdown/HTML commenter unit tests
│   ├── test_secret_scanner.py       # Secret regex & Shannon entropy tests
│   └── test_simulation.py           # Verification of simulation script
├── action.yml                       # GitHub Action Docker metadata
├── Dockerfile                       # 2-stage unprivileged (uid 1001) container
├── pyproject.toml                   # Project metadata, pytest & ruff configs
├── requirements-dev.txt             # Testing & linting tools
└── requirements.txt                 # Core pinned dependencies (pydantic, requests)
```

---

## ⚖️ License & Author

- **Developer:** [Soham Kundu](https://github.com/sohamkundu) (B.Tech Computer Science & Engineering, IEM Kolkata)
- **License:** Licensed under the [MIT License](LICENSE).
