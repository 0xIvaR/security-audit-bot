# Multi-Repo Deployment Guide — Automated GitHub PR Security Audit Bot

This guide provides instructions for deploying the **Automated GitHub PR Security Audit Bot** across multiple repositories within your GitHub organization with **zero SaaS dependencies** and **zero configuration**.

---

## 1. Supported Architectures & Topologies

The Security Audit Bot is designed to drop cleanly into any repository type:

| Repository Type | Target Assets Audited | Example Stack | Scan SLA |
| :--- | :--- | :--- | :---: |
| **Python Backend / Microservice** | Added `.py` lines, `requirements.txt` | FastAPI, Django, Flask, SQLAlchemy | $< 1.2\text{s}$ |
| **Fullstack Monorepo** | Python backend, Node frontend (`package.json`), Secrets | React + FastAPI, Next.js + Flask | $< 2.4\text{s}$ |
| **Open-Source CLI / Tooling** | Added source diffs, configuration files, manifests | Python 3.11+, Click, Typer | $< 0.8\text{s}$ |

---

## 2. Drop-in Deployment (3 Steps)

### Step 1: Copy Workflow File
Copy the workflow configuration into the target repository at `.github/workflows/security-audit.yml`:

```yaml
name: "Security Audit Bot"

on:
  pull_request:
    types: [opened, synchronize, reopened]
    branches:
      - main
      - master
      - "release/**"

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: security-audit-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  security-audit:
    name: "Static Security Analysis & Policy Gate"
    runs-on: ubuntu-latest
    timeout-minutes: 5

    steps:
      - name: "Checkout Repository with Full Git History"
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: "Run Security Audit Bot"
        uses: 0xIvaR/security-audit-bot@master
        with:
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
          repo: ${{ github.repository }}
          pr-number: ${{ github.event.pull_request.number }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Step 2: Configure Repository Permissions
Navigate to **Settings -> Actions -> General -> Workflow permissions**:
- Select **Read and write permissions** (required to upsert PR comments via `GITHUB_TOKEN`).
- Check **Allow GitHub Actions to create and approve pull requests** (optional).

### Step 3: Open a Verification Pull Request
Create a branch and test the deployment:
1. **Clean Test PR:** Add a standard Python function or update documentation.
   - Expected Output: Bot comments with `✅ Security Audit Passed` and workflow exits with code `0`.
2. **Vulnerability Test PR:** Add a test credential (e.g. dummy Slack token `xoxb-...`) or dynamic SQL execution (`cursor.execute(f"SELECT ... {id}")`).
   - Expected Output: Bot comments with `❌ Security Audit Failed — Merge Blocked`, collapsible remediation snippets, and workflow exits with code `1`.

---

## 3. Deploying Across Multiple Repositories

### Scenario 1: Python Microservice (`service-auth`)
- **Key Focus:** Preventing secret leakage and OWASP injection in auth handlers.
- **Workflow:** Standard `.github/workflows/security-audit.yml`.
- **Manifest:** Audits `requirements.txt` via OSV.dev batch endpoint in $< 650\text{ ms}$.

### Scenario 2: Fullstack Monorepo (`app-platform`)
- **Key Focus:** Scanning both Python backend and Node.js frontend (`package.json`) dependencies.
- **Behavior:** The scanner automatically audits all detected manifests in the PR diff:
  - PyPI: `requirements.txt`
  - npm: `package.json`

### Scenario 3: Open-Source Library (`py-data-tools`)
- **Key Focus:** Public contributions and forks.
- **Fork Pull Requests:** Pull requests from forks receive read-only permissions by default for security. The bot supports running with `--dry-run` to output results directly into the GitHub Actions step log without failing if `pull-requests: write` is restricted.

---

## 4. Local Execution & Pre-Commit Hook

Developers can run the audit bot locally before pushing code to avoid CI failures:

```bash
# Offline dry run comparing against master
python -m src.main --base origin/master --head HEAD --dry-run

# Export interactive dark-mode HTML report
python -m src.main --base origin/master --head HEAD --html-report audit_report.html
```

Or add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: local
    hooks:
      - id: security-audit-bot
        name: Security Audit Bot
        entry: python -m src.main --base HEAD~1 --head HEAD --dry-run
        language: system
        stages: [commit]
```
