<!-- security-audit-bot-v1 -->
## 🛡️ CI Security Audit Report — Action Required

> [!CAUTION]
> **Merge Blocked:** Automated security audit detected **3** blocking issue(s) (`CRITICAL` or `HIGH`). Please resolve the flagged items below before merging.

### 📊 Scan Summary
| Metric | Value | Status |
| :--- | :--- | :--- |
| **Audit Status** | `FAILED (Merge Blocked)` | ❌ `sys.exit(1)` |
| **Total PR Execution Time** | `42 ms` (< 4,800 ms SLA) | ⚡ Within Budget |
| **Files Modified & Scanned** | `3 files` | 🔍 Unified Diff Scoped |
| **Critical Issues** | `2` | 🔴 Immediate Remediation Required |
| **High Issues** | `1` | 🟠 High Risk Vulnerability |
| **Medium Warnings** | `0` | 🟡 Non-blocking Advisory |

---

### 🚨 Detected Security Findings (3)

| Severity | Rule ID | Location | Vulnerability Description | Suggested Fix |
| :---: | :---: | :--- | :--- | :--- |
| 🔴 **CRITICAL** | `SEC-001` | `src/config/aws.py:14` | Hardcoded AWS Access Key ID detected. Token: AKIA************D123 | Immediately revoke this key in AWS IAM and inject credentials via GitHub Secrets/environment variables. |
| 🔴 **CRITICAL** | `AST-004` | `src/database/queries.py:1` | SQL Injection: Dynamic SQL constructed via f-string (ast.JoinedStr) passed to .execute(). | Use parameterized queries passing arguments as tuple parameters, e.g. cursor.execute('SELECT ... %s', (val,)). |
| 🟠 **HIGH** | `DEP-OSV` | `requirements.txt:7` | Vulnerable to CVE-2018-18074 (Session fixation / credential leak on cross-domain redirect). | Upgrade requests to >=2.31.0 in requirements.txt. |

---

### 🔍 Detailed Findings & Remediation Guides

<details>
<summary>🔴 <b>[SEC-001] Exposed AWS Access Key ID in <code>src/config/aws.py:14</code></b></summary>
<br>

**Rule ID:** `SEC-001` | **Category:** `SECRET`  
**Description:** Hardcoded AWS Access Key ID detected. Token: AKIA************D123

**Vulnerable Code:**
```python
# src/config/aws.py:14
AWS_ACCESS_KEY_ID = "AKIA************D123"
```

**Recommended Remediation:**
Immediately revoke this key in AWS IAM and inject credentials via GitHub Secrets/environment variables.

</details>

<details>
<summary>🔴 <b>[AST-004] OWASP SQL Injection Sink in <code>src/database/queries.py:1</code></b></summary>
<br>

**Rule ID:** `AST-004` | **Category:** `AST_OWASP`  
**Description:** SQL Injection: Dynamic SQL constructed via f-string (ast.JoinedStr) passed to .execute().

**Vulnerable Code:**
```python
# src/database/queries.py:1
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Recommended Remediation:**
Use parameterized queries passing arguments as tuple parameters, e.g. cursor.execute('SELECT ... %s', (val,)).

</details>

<details>
<summary>🟠 <b>[DEP-OSV] Vulnerable Dependency: requests@2.19.1 in <code>requirements.txt:7</code></b></summary>
<br>

**Rule ID:** `DEP-OSV` | **Category:** `DEPENDENCY_CVE`  
**Description:** Vulnerable to CVE-2018-18074 (Session fixation / credential leak on cross-domain redirect).

**Vulnerable Code:**
```text
# requirements.txt:7
requests==2.19.1
```

**Recommended Remediation:**
Upgrade requests to >=2.31.0 in requirements.txt.

</details>

---

<sub>🤖 Automated by **GitHub PR Security Audit Bot v1.0.0** • Scanned commit [`feat/ad`] • Execution Latency: `42 ms`</sub>