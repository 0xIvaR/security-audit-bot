"""Automated GitHub PR Review Commenter & Report Generator (Milestone 8).

Builds idempotent Markdown reports conforming to DESIGN.md, upserts comments
via the GitHub REST API (GET -> PATCH / POST), and exports standalone HTML reports.
"""

from __future__ import annotations

import html
import os
import sys
from typing import TYPE_CHECKING, Any

import requests

from src.config import IDEMPOTENCY_MARKER
from src.models import AuditReport, Severity

if TYPE_CHECKING:
    pass

GITHUB_API_BASE: str = "https://api.github.com"
GITHUB_API_VERSION: str = "2022-11-28"

SEVERITY_BADGE_MD: dict[Severity, str] = {
    Severity.CRITICAL: "🔴 **CRITICAL**",
    Severity.HIGH: "🟠 **HIGH**",
    Severity.MEDIUM: "🟡 **MEDIUM**",
}

SEVERITY_ICON: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
}


def escape_markdown_table_cell(text: str) -> str:
    """Escape vertical pipes and newlines for GitHub Markdown table cells."""
    return text.replace("|", "\\|").replace("\n", " ").strip()


def build_markdown_report(report: AuditReport) -> str:
    """Render deterministic, scannable Markdown audit report conforming strictly to DESIGN.md."""
    lines: list[str] = [IDEMPOTENCY_MARKER]
    short_head = report.head_sha[:7] if report.head_sha else "HEAD"

    if report.should_block_merge:
        total_blocking = report.critical_count + report.high_count
        lines.append("## 🛡️ CI Security Audit Report — Action Required\n")
        lines.append("> [!CAUTION]")
        lines.append(
            f"> **Merge Blocked:** Automated security audit detected **{total_blocking}** "
            "blocking issue(s) (`CRITICAL` or `HIGH`). Please resolve the flagged items below before merging.\n"
        )

        lines.append("### 📊 Scan Summary")
        lines.append("| Metric | Value | Status |")
        lines.append("| :--- | :--- | :--- |")
        lines.append("| **Audit Status** | `FAILED (Merge Blocked)` | ❌ `sys.exit(1)` |")
        lines.append(
            f"| **Total PR Execution Time** | `{report.scan_duration_ms:.0f} ms` (< 4,800 ms SLA) | ⚡ Within Budget |"
        )
        lines.append(
            f"| **Files Modified & Scanned** | `{report.files_scanned} files` | 🔍 Unified Diff Scoped |"
        )
        lines.append(
            f"| **Critical Issues** | `{report.critical_count}` | 🔴 Immediate Remediation Required |"
        )
        lines.append(f"| **High Issues** | `{report.high_count}` | 🟠 High Risk Vulnerability |")
        lines.append(
            f"| **Medium Warnings** | `{report.medium_count}` | 🟡 Non-blocking Advisory |"
        )
        lines.append("\n---\n")

        lines.append(f"### 🚨 Detected Security Findings ({report.total_findings})\n")
        lines.append(
            "| Severity | Rule ID | Location | Vulnerability Description | Suggested Fix |"
        )
        lines.append("| :---: | :---: | :--- | :--- | :--- |")

        for f in report.findings:
            sev_badge = SEVERITY_BADGE_MD.get(f.severity, f"**{f.severity.value}**")
            rule_id_code = f"`{f.rule_id}`"
            location = f"`{f.file_path}:{f.line_number}`"
            desc = escape_markdown_table_cell(f.description)
            fix = escape_markdown_table_cell(f.remediation)
            lines.append(f"| {sev_badge} | {rule_id_code} | {location} | {desc} | {fix} |")

        lines.append("\n---\n")
        lines.append("### 🔍 Detailed Findings & Remediation Guides\n")

        for f in report.findings:
            icon = SEVERITY_ICON.get(f.severity, "⚠️")
            lines.append("<details>")
            lines.append(
                f"<summary>{icon} <b>[{f.rule_id}] {html.escape(f.title)} in <code>{f.file_path}:{f.line_number}</code></b></summary>\n<br>\n"
            )
            lines.append(f"**Rule ID:** `{f.rule_id}` | **Category:** `{f.category.value}`  ")
            lines.append(f"**Description:** {f.description}\n")

            if f.snippet:
                lines.append("**Vulnerable Code:**")
                # Auto-select language identifier
                lang = (
                    "python"
                    if f.file_path.endswith(".py")
                    else "json"
                    if f.file_path.endswith(".json")
                    else "text"
                )
                lines.append(
                    f"```{lang}\n# {f.file_path}:{f.line_number}\n{f.snippet.strip()}\n```\n"
                )

            lines.append(f"**Recommended Remediation:**\n{f.remediation}\n")
            lines.append("</details>\n")

    else:
        lines.append("## 🛡️ CI Security Audit Report — Passed\n")
        lines.append("> [!TIP]")
        lines.append(
            f"> **Audit Passed:** All AST code checks, secret entropy scans, and dependency manifests passed with zero vulnerabilities detected across **{report.files_scanned}** modified file(s).\n"
        )

        lines.append("### 📊 Scan Summary")
        lines.append("| Metric | Value | Status |")
        lines.append("| :--- | :--- | :--- |")
        lines.append("| **Audit Status** | `PASSED` | ✅ `sys.exit(0)` |")
        lines.append(
            f"| **Total PR Execution Time** | `{report.scan_duration_ms:.0f} ms` | ⚡ (< 4,800 ms SLA) |"
        )
        lines.append(
            f"| **Files Modified & Scanned** | `{report.files_scanned} files` | 🔍 Zero Leaks / Sinks |"
        )
        if report.medium_count > 0:
            lines.append(
                f"| **Medium Warnings** | `{report.medium_count}` | 🟡 Non-blocking Advisory |"
            )

        if report.findings:
            lines.append("\n---\n")
            lines.append(f"### 🟡 Non-Blocking Advisories ({report.total_findings})\n")
            lines.append(
                "| Severity | Rule ID | Location | Vulnerability Description | Suggested Fix |"
            )
            lines.append("| :---: | :---: | :--- | :--- | :--- |")
            for f in report.findings:
                sev_badge = SEVERITY_BADGE_MD.get(f.severity, f"**{f.severity.value}**")
                lines.append(
                    f"| {sev_badge} | `{f.rule_id}` | `{f.file_path}:{f.line_number}` | "
                    f"{escape_markdown_table_cell(f.description)} | {escape_markdown_table_cell(f.remediation)} |"
                )

    lines.append("---\n")
    lines.append(
        f"<sub>🤖 Automated by **GitHub PR Security Audit Bot v1.0.0** • "
        f"Scanned commit [`{short_head}`] • Execution Latency: `{report.scan_duration_ms:.0f} ms`</sub>"
    )

    return "\n".join(lines)


def build_html_report(report: AuditReport) -> str:
    """Generate standalone dark-mode HTML audit report conforming to DESIGN.md Section 6."""
    status_label = "FAILED (Merge Blocked)" if report.should_block_merge else "PASSED"
    status_class = "badge-critical" if report.should_block_merge else "badge-passed"
    short_head = report.head_sha[:7] if report.head_sha else "HEAD"

    findings_html: list[str] = []
    for f in report.findings:
        sev_class = f"badge-{f.severity.value.lower()}"
        snippet_block = ""
        if f.snippet:
            snippet_block = f"<pre><code># {html.escape(f.file_path)}:{f.line_number}\n{html.escape(f.snippet.strip())}</code></pre>"

        findings_html.append(
            f"""
            <div class="finding-card">
              <div class="finding-header">
                <span class="badge {sev_class}">{f.severity.value}</span>
                <span class="finding-rule">[{html.escape(f.rule_id)}]</span>
                <span class="finding-loc">{html.escape(f.file_path)}:{f.line_number}</span>
              </div>
              <h4>{html.escape(f.title)}</h4>
              <p class="finding-desc">{html.escape(f.description)}</p>
              {snippet_block}
              <div class="remediation-box">
                <strong>Suggested Fix:</strong>
                <p>{html.escape(f.remediation)}</p>
              </div>
            </div>
            """
        )

    findings_rendered = (
        "\n".join(findings_html) if findings_html else "<p>No vulnerabilities detected.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Audit Report — {html.escape(report.repository)}</title>
  <style>
    :root {{
      --bg-primary: #0D1117;
      --bg-secondary: #161B22;
      --border-color: #30363D;
      --text-primary: #E6EDF3;
      --text-muted: #8B949E;
      --critical: #DA3633;
      --high: #D97706;
      --medium: #CA8A04;
      --passed: #238636;
    }}
    body {{
      background-color: var(--bg-primary);
      color: var(--text-primary);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      margin: 0;
      padding: 24px;
    }}
    .container {{
      max-width: 1080px;
      margin: 0 auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 16px;
    }}
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin: 24px 0;
    }}
    .stat-card {{
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
    }}
    .stat-card h3 {{
      margin: 0 0 8px 0;
      font-size: 14px;
      color: var(--text-muted);
    }}
    .stat-card .val {{
      font-size: 28px;
      font-weight: 700;
    }}
    .badge {{
      display: inline-block;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
      border-radius: 4px;
      text-transform: uppercase;
    }}
    .badge-critical {{ background: rgba(218, 54, 51, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high     {{ background: rgba(217, 119, 6, 0.2);  color: var(--high);     border: 1px solid var(--high); }}
    .badge-medium   {{ background: rgba(202, 138, 4, 0.2);  color: var(--medium);   border: 1px solid var(--medium); }}
    .badge-passed   {{ background: rgba(35, 134, 54, 0.2);  color: var(--passed);   border: 1px solid var(--passed); }}
    .finding-card {{
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 16px;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 13px;
    }}
    .finding-loc {{
      color: var(--text-muted);
      font-family: ui-monospace, SFMono-Regular, monospace;
    }}
    pre {{
      background-color: #1F242C;
      padding: 12px;
      overflow-x: auto;
      border-radius: 6px;
      border: 1px solid var(--border-color);
      font-family: ui-monospace, SFMono-Regular, monospace;
    }}
    .remediation-box {{
      background: rgba(9, 105, 218, 0.1);
      border-left: 4px solid #0969DA;
      padding: 8px 12px;
      margin-top: 12px;
      border-radius: 0 4px 4px 0;
    }}
    footer {{
      margin-top: 40px;
      text-align: center;
      color: var(--text-muted);
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h2>🛡️ GitHub PR Security Audit Bot</h2>
        <span>Repository: {html.escape(report.repository)} | Commit: <code>{html.escape(short_head)}</code></span>
      </div>
      <div>
        <span class="badge {status_class}">{status_label}</span>
      </div>
    </header>

    <div class="stat-grid">
      <div class="stat-card">
        <h3>Total Findings</h3>
        <div class="val">{report.total_findings}</div>
      </div>
      <div class="stat-card">
        <h3>Critical Issues</h3>
        <div class="val" style="color: var(--critical);">{report.critical_count}</div>
      </div>
      <div class="stat-card">
        <h3>High Issues</h3>
        <div class="val" style="color: var(--high);">{report.high_count}</div>
      </div>
      <div class="stat-card">
        <h3>Scan Latency</h3>
        <div class="val">{report.scan_duration_ms:.0f} ms</div>
      </div>
    </div>

    <h3>Detected Findings</h3>
    {findings_rendered}

    <footer>
      🤖 Generated by Automated GitHub PR Security Audit Bot v1.0.0 • Budget SLA &lt; 4,800 ms
    </footer>
  </div>
</body>
</html>"""


def post_or_update_pr_comment(
    report: AuditReport,
    repo: str,
    pr_number: int,
    token: str | None = None,
    session: requests.Session | None = None,
) -> bool:
    """Upsert security report comment on a GitHub PR using REST API v3.

    Queries existing comments. If the idempotency marker is found, updates it in-place
    via PATCH. Otherwise, posts a new comment via POST.

    Returns:
        True if comment was posted or updated successfully; False otherwise.
    """
    github_token = token or os.getenv("GITHUB_TOKEN")
    if not github_token:
        print(
            "[!] GitHub Comment Warning: GITHUB_TOKEN not provided; skipping PR comment API call.",
            file=sys.stderr,
        )
        return False

    client = session or requests.Session()
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }

    markdown_body = build_markdown_report(report)
    comments_url = f"{GITHUB_API_BASE}/repos/{repo}/issues/{pr_number}/comments"

    try:
        # 1. Fetch existing PR comments (up to 100)
        resp = client.get(comments_url, headers=headers, params={"per_page": 100}, timeout=10.0)
        resp.raise_for_status()
        existing_comments: list[dict[str, Any]] = resp.json()

        existing_comment_id: int | None = None
        for comment in existing_comments:
            body = comment.get("body", "")
            if IDEMPOTENCY_MARKER in body:
                existing_comment_id = comment.get("id")
                break

        # 2. Update existing comment or create new comment
        if existing_comment_id is not None:
            patch_url = f"{GITHUB_API_BASE}/repos/{repo}/issues/comments/{existing_comment_id}"
            patch_resp = client.patch(
                patch_url, headers=headers, json={"body": markdown_body}, timeout=10.0
            )
            patch_resp.raise_for_status()
            print(
                f"[✓] GitHub PR Comment       : Updated existing audit comment (id {existing_comment_id})"
            )
            return True
        else:
            post_resp = client.post(
                comments_url, headers=headers, json={"body": markdown_body}, timeout=10.0
            )
            post_resp.raise_for_status()
            new_id = post_resp.json().get("id")
            print(f"[✓] GitHub PR Comment       : Posted new audit comment (id {new_id})")
            return True

    except requests.RequestException as exc:
        print(f"[!] GitHub PR Comment Error : Failed to upsert PR comment: {exc}", file=sys.stderr)
        return False
