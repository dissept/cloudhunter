# engine/report.py
# generates a nice HTML report from the CSV findings
# much easier to read than raw CSV, and looks good for the demo
# the style is dark themed to match the Cloudhunter branding

import csv
import webbrowser
from datetime import datetime, timezone
from pathlib import Path


def generate_html_report(csv_path: str, html_path: str, mode: str = "live") -> str:
    # read all the findings from the CSV
    with open(csv_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total     = len(rows)
    highs     = sum(1 for r in rows if r["severity"] == "high")
    mediums   = sum(1 for r in rows if r["severity"] == "medium")

    # build the finding rows for the table
    finding_rows = ""
    for r in rows:
        sev = r["severity"]
        sev_class = "high" if sev == "high" else "medium"

        finding_rows += f"""
        <tr>
            <td>{r["resource_id"]}</td>
            <td>{r["resource_type"]}</td>
            <td class="{sev_class}">{sev.upper()}</td>
            <td>{r["cvss_score"]}</td>
            <td><a href="{r["mitre_url"]}" target="_blank">{r["mitre_id"]}</a></td>
            <td>{r["mitre_name"]}</td>
            <td>{r["title"]}</td>
        </tr>"""

    # demo banner shown at top if running in demo mode
    demo_banner = ""
    if mode == "demo":
        demo_banner = """
        <div class="demo-banner">
            ⚠ DEMO MODE — Synthetic findings. CVSS and MITRE mapping are real (same code path).
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloudhunter — Scan Report</title>
    <style>
        body {{
            background: #111;
            color: #ddd;
            font-family: monospace;
            padding: 2rem;
            font-size: 14px;
        }}
        h1 {{ color: #a78bfa; margin-bottom: 0.3rem; }}
        p.meta {{ color: #666; margin-bottom: 1.5rem; }}
        .demo-banner {{
            background: #1a1400;
            border-left: 3px solid #f59e0b;
            color: #f59e0b;
            padding: 0.5rem 1rem;
            margin-bottom: 1.5rem;
        }}
        .summary {{ margin-bottom: 1.5rem; color: #aaa; }}
        .summary span {{ margin-right: 1.5rem; }}
        .high   {{ color: #f87171; }}
        .medium {{ color: #fb923c; }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 0.5rem 0.75rem;
            border-bottom: 1px solid #333;
            color: #a78bfa;
        }}
        td {{
            padding: 0.5rem 0.75rem;
            border-bottom: 1px solid #222;
            vertical-align: top;
        }}
        a {{ color: #a78bfa; }}
        footer {{ margin-top: 2rem; color: #444; font-size: 12px; }}
    </style>
</head>
<body>

<h1>CLOUDHUNTER — Scan Report</h1>
<p class="meta">Scan time: {scan_time} | Mode: {mode.upper()}</p>

{demo_banner}

<div class="summary">
    <span>Total: <strong>{total}</strong></span>
    <span class="high">High: <strong>{highs}</strong></span>
    <span class="medium">Medium: <strong>{mediums}</strong></span>
</div>

<table>
    <thead>
        <tr>
            <th>Resource</th>
            <th>Type</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>MITRE</th>
            <th>Technique</th>
            <th>Finding</th>
        </tr>
    </thead>
    <tbody>
        {finding_rows}
    </tbody>
</table>

<footer>Cloudhunter — BSc Computer Science (Cybersecurity) | read-only | CVSS v3.1 | MITRE ATT&CK Cloud</footer>

</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    return html_path
