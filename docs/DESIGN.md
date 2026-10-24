# DESIGN.md — Visual & Interface Design Specification
## Automated GitHub PR Security Audit Bot

---

## 1. Design Purpose & Output Surfaces

The **Automated GitHub PR Security Audit Bot** delivers feedback across three distinct user interfaces:
1. **GitHub Pull Request Markdown Comment (Primary UI):** The developer-facing report posted directly on GitHub pull requests. It must be clean, dense, scannable, non-intrusive, and strictly idempotent.
2. **CLI Terminal Output (Developer & CI Runner UI):** Formatted ANSI terminal output rendered during local runs (`--dry-run`) or inside GitHub Actions workflow run logs.
3. **Static HTML Audit Report (Optional Local Preview UI):** An exportable, self-contained single-page dashboard for offline inspection.

This document establishes the exact design tokens, typography, component layouts, spacing, and styling rules to ensure deterministic output across all AI coding generators.

---

## 2. Color Palette & Design Tokens

### 2.1 Severity Color Tokens
All interfaces must strictly adhere to these semantic status colors:

| Severity Tier | Hex Code | RGB | ANSI Terminal Escape | GitHub Markdown Badge Token | Meaning / Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | `#DA3633` | `rgb(218, 54, 51)` | `\033[1;31m` (Bold Red) | `https://img.shields.io/badge/CRITICAL-DA3633?style=flat-square` | Merge-blocking; secret leak or direct RCE/SQLi |
| **HIGH** | `#D97706` | `rgb(217, 119, 6)` | `\033[1;33m` (Bold Amber) | `https://img.shields.io/badge/HIGH-D97706?style=flat-square` | Merge-blocking; command execution, dangerous CVE |
| **MEDIUM** | `#CA8A04` | `rgb(202, 138, 4)` | `\033[0;33m` (Yellow) | `https://img.shields.io/badge/MEDIUM-CA8A04?style=flat-square` | Non-blocking warning; weak hash, outdated package |
| **PASSED / CLEAN**| `#238636` | `rgb(35, 134, 54)` | `\033[1;32m` (Bold Green) | `https://img.shields.io/badge/PASSED-238636?style=flat-square` | Zero blocking issues found; PR approved |
| **INFO / METRIC** | `#0969DA` | `rgb(9, 105, 218)` | `\033[0;36m` (Cyan) | `https://img.shields.io/badge/AUDIT-0969DA?style=flat-square` | Timing stats, SHA references, file counts |

### 2.2 Surface & Neutral Tokens (Dark Mode Default)

| Token Name | Hex Code | CSS Variable | Purpose |
| :--- | :--- | :--- | :--- |
| `bg-canvas-default` | `#0D1117` | `--color-canvas-default` | Main background for HTML preview |
| `bg-canvas-subtle` | `#161B22` | `--color-canvas-subtle` | Card, container, and table header background |
| `border-default` | `#30363D` | `--color-border-default` | Table borders, card dividers, code blocks |
| `border-muted` | `#21262D` | `--color-border-muted` | Inner sub-dividers, table row separators |
| `fg-default` | `#E6EDF3` | `--color-fg-default` | Primary text and headers |
| `fg-muted` | `#8B949E` | `--color-fg-muted` | Secondary metadata, captions, timestamps |
| `code-bg` | `#1F242C` | `--color-code-bg` | Inline code chips and diff blocks |

---

## 3. Typography & Formatting Standards

### 3.1 Font Stacks
* **Prose & Body:** `-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif`
* **Monospace & Code:** `ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`

### 3.2 Standard Severity Badges & Status Icons
When rendering Markdown or Terminal output, use these exact prefix combinations:

* **CRITICAL:** `🔴 **CRITICAL**` (Markdown) | `[CRITICAL]` (CLI)
* **HIGH:** `🟠 **HIGH**` (Markdown) | `[HIGH]` (CLI)
* **MEDIUM:** `🟡 **MEDIUM**` (Markdown) | `[MEDIUM]` (CLI)
* **PASSED:** `🟢 **PASSED**` (Markdown) | `[PASSED]` (CLI)

---

## 4. GitHub PR Review Comment Layout Specification (Primary UI)

The comment posted on GitHub Pull Requests must match this exact layout structure.

### 4.1 Invisible Idempotency Anchor
Every generated comment must begin with this exact HTML comment tag on line 1:
```html
<!-- security-audit-bot-v1 -->
```
*(The bot queries PR comments for this string to update via `PATCH` rather than creating duplicate comments).*

### 4.2 State A: Merge-Blocked Layout (Violations Detected)

```markdown
<!-- security-audit-bot-v1 -->
## 🛡️ CI Security Audit Report — Action Required

> [!CAUTION]
> **Merge Blocked:** Automated security audit detected **{total_blocking}** blocking issue(s) (`CRITICAL` or `HIGH`). Please resolve the flagged items below before merging.

### 📊 Scan Summary
| Metric | Value | Status |
| :--- | :--- | :--- |
| **Audit Status** | `FAILED (Merge Blocked)` | ❌ `sys.exit(1)` |
| **Total PR Execution Time** | `{scan_duration_ms:.0f} ms` (< 4,800 ms SLA) | ⚡ Within Budget |
| **Files Modified & Scanned** | `{files_scanned} files` | 🔍 Unified Diff Scoped |
| **Critical Issues** | `{critical_count}` | 🔴 Immediate Remediation Required |
| **High Issues** | `{high_count}` | 🟠 High Risk Vulnerability |
| **Medium Warnings** | `{medium_count}` | 🟡 Non-blocking Advisory |

---

### 🚨 Detected Security Findings ({total_findings})

| Severity | Rule ID | Location | Vulnerability Description | Suggested Fix |
| :---: | :---: | :--- | :--- | :--- |
| 🔴 **CRITICAL** | `AST-004` | `app/db.py:42` | SQL Injection via dynamic f-string formatting | Use parameterized query tuples |
| 🔴 **CRITICAL** | `SEC-001` | `config/aws.py:12` | Leaked AWS Access Key (`AKIA************7X9Q`) | Revoke key and inject via GitHub Secrets |
| 🟠 **HIGH** | `AST-001` | `utils/calc.py:88` | Unsafe code execution sink (`eval()`) | Replace with `ast.literal_eval()` |
| 🟠 **HIGH** | `DEP-OSV` | `requirements.txt:9` | Known CVE in `requests==2.19.0` (CVE-2018-18074) | Upgrade to `>=2.20.0` |

---

### 🔍 Detailed Findings & Remediation Guides

<details>
<summary>🔴 <b>[AST-004] SQL Injection in <code>app/db.py:42</code></b></summary>

<br>

**Rule ID:** `AST-004` | **Category:** `OWASP Top-10 A03:2021-Injection`  
**Description:** Dynamic SQL query constructed via f-string interpolation (`ast.JoinedStr`) inside `.execute()`. An attacker can manipulate input parameters to execute arbitrary SQL commands.

**Vulnerable Code:**
```python
# app/db.py:42
cursor.execute(f"SELECT * FROM users WHERE email = '{user_input}'")
```

**Recommended Remediation:**
```python
# app/db.py:42 (Use parameterized tuple)
cursor.execute("SELECT * FROM users WHERE email = %s", (user_input,))
```
</details>

<details>
<summary>🔴 <b>[SEC-001] Leaked AWS Access Key in <code>config/aws.py:12</code></b></summary>

<br>

**Rule ID:** `SEC-001` | **Category:** `Hardcoded Credentials (CWE-798)`  
**Description:** Hardcoded AWS Access Key ID detected matching pattern `AKIA[0-9A-Z]{16}`.

**Redacted Token Snippet:**
```text
AWS_KEY = "AKIA************7X9Q"
```

**Recommended Remediation:**
1. Immediately **revoke** this key in the AWS IAM Console.
2. Replace hardcoded string with environment variable injection:
```python
import os
AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
```
</details>

---

<sub>🤖 Automated by **GitHub PR Security Audit Bot v1.0.0** • Scanned commit [`{head_sha[:7]}`] • Execution Latency: `{scan_duration_ms:.0f} ms`</sub>
```

---

### 4.3 State B: Passed Clean Layout (Zero Violations Detected)

```markdown
<!-- security-audit-bot-v1 -->
## 🛡️ CI Security Audit Report — Passed

> [!TIP]
> **Audit Passed:** All AST code checks, secret entropy scans, and dependency manifests passed with zero vulnerabilities detected across **{files_scanned}** modified file(s).

### 📊 Scan Summary
| Metric | Value | Status |
| :--- | :--- | :--- |
| **Audit Status** | `PASSED` | ✅ `sys.exit(0)` |
| **Total PR Execution Time** | `{scan_duration_ms:.0f} ms` | ⚡ (< 4,800 ms SLA) |
| **Modified Lines Inspected** | `{total_added_lines} lines` | 🔍 Zero Leaks / Sinks |
| **Dependencies Checked** | `{deps_checked} packages` | 📦 OSV.dev Batch Clean |

<sub>🤖 Automated by **GitHub PR Security Audit Bot v1.0.0** • Scanned commit [`{head_sha[:7]}`]</sub>
```

---

## 5. CLI Terminal Output Design (CLI & Actions Logs)

When executed via command-line (`python -m src.main`), the output must be rendered with structured ANSI styling:

```text
================================================================================
           🛡️  GITHUB PR SECURITY AUDIT BOT — STATIC SCANNER v1.0.0
================================================================================
Target Repository : owner/repo
Diff Comparison   : base (a1b2c3d) ... head (e5f6a7b)
Scan Mode         : Pull Request Scoped (Modified '+' Lines Only)
--------------------------------------------------------------------------------
[✓] Git Diff Parsed         : 4 files modified (82 added lines) [124 ms]
[✓] Hybrid Secret Scanner   : 0 leaks detected (Entropy > 4.5 bits/char) [310 ms]
[!] AST Static Analyzer     : 2 vulnerabilities flagged [480 ms]
[✓] OSV.dev Dependency Scan : 18 packages audited in batch [520 ms]
--------------------------------------------------------------------------------

🚨 FINDINGS (2 issues detected):

  [CRITICAL] AST-004: SQL Injection via dynamic f-string
  Location : app/db.py:42
  Snippet  : cursor.execute(f"SELECT * FROM users WHERE email = '{user_input}'")
  Fix      : Use parameterized queries: cursor.execute("...", (param,))

  [HIGH]     AST-001: Dangerous code execution sink (eval)
  Location : utils/calc.py:88
  Snippet  : result = eval(user_expression)
  Fix      : Replace with ast.literal_eval() or deterministic parsing

--------------------------------------------------------------------------------
SCAN RESULT   : FAILED (Merge Blocked)
EXIT STATUS   : sys.exit(1)
TOTAL LATENCY : 1,434 ms (Budget: < 4,800 ms)
================================================================================
```

---

## 6. Static HTML Report Styling Specification (Local Preview)

If `--html-report <output.html>` is requested, generate a single self-contained HTML file styled with modern CSS.

### 6.1 HTML Layout Hierarchy
```text
┌────────────────────────────────────────────────────────┐
│ Header: Logo, Repo Name, PR Number, Status Badge       │
├────────────────────────────────────────────────────────┤
│ Summary Stat Grid: 4 Metric Cards (Total, Critical,    │
│                    High, Scan Duration)                │
├────────────────────────────────────────────────────────┤
│ Interactive Filter Bar: [All] [Critical] [High] [Med]  │
├────────────────────────────────────────────────────────┤
│ Findings Table / Card List: Collapsible Remediation    │
│                             Code Blocks                │
├────────────────────────────────────────────────────────┤
│ Footer: Timestamps, Engine Version, GitHub Token Scope │
└────────────────────────────────────────────────────────┘
```

### 6.2 Embedded CSS Specification (Mandatory Styling Rules)
```css
:root {
  --bg-primary: #0D1117;
  --bg-secondary: #161B22;
  --border-color: #30363D;
  --text-primary: #E6EDF3;
  --text-muted: #8B949E;
  --critical: #DA3633;
  --high: #D97706;
  --medium: #CA8A04;
  --passed: #238636;
}

body {
  background-color: var(--bg-primary);
  color: var(--text-primary);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  margin: 0;
  padding: 24px;
}

.container {
  max-width: 1080px;
  margin: 0 auto;
}

.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin: 20px 0;
}

.stat-card {
  background-color: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
}

.badge {
  display: inline-block;
  padding: 4px 8px;
  font-size: 12px;
  font-weight: 700;
  border-radius: 4px;
  text-transform: uppercase;
}
.badge-critical { background: rgba(218, 54, 51, 0.2); color: var(--critical); border: 1px solid var(--critical); }
.badge-high     { background: rgba(217, 119, 6, 0.2);  color: var(--high);     border: 1px solid var(--high); }
.badge-medium   { background: rgba(202, 138, 4, 0.2);  color: var(--medium);   border: 1px solid var(--medium); }
.badge-passed   { background: rgba(35, 134, 54, 0.2);  color: var(--passed);   border: 1px solid var(--passed); }

code, pre {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  background-color: #1F242C;
  border-radius: 6px;
}

pre {
  padding: 12px;
  overflow-x: auto;
  border: 1px solid var(--border-color);
}
```

---

## 7. Component Anti-Drift Guardrails

To prevent AI from generating messy or non-standard visual elements:
1. **Never use raw un-redacted secrets:** The secret scanner MUST run `redact_secret()` (`AKIA************7X9Q`) before injecting values into any UI element.
2. **Never create floating un-anchored PR comments:** The hidden tag `<!-- security-audit-bot-v1 -->` is required in every Markdown comment generation function.
3. **Never emit non-standard severity levels:** Only `CRITICAL`, `HIGH`, and `MEDIUM` are permissible. Do not use `LOW`, `INFO`, `NOTICE`, or `WARNING` as finding severity levels.
4. **Always include code snippet and remediation pair:** Every detailed finding card must provide both the vulnerable snippet and its concrete safe alternative.