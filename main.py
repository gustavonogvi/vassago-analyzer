import argparse
import html
import json
import sys
from datetime import datetime
from pathlib import Path

from analyzer.engine import run_analysis, run_analysis_from_api
from analyzer.rules import Alert

BOLD  = "\033[1m"
RESET = "\033[0m"

SEVERITY_COLOR = {
    "LOW":      "\033[33m",
    "MEDIUM":   "\033[38;5;208m",
    "HIGH":     "\033[31m",
    "CRITICAL": "\033[35m",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus — SSH Log Analyzer for Naberius-Honeypot",
    )
    parser.add_argument(
        "--db",
        default="data/naberius.db",
        help="Path to Naberius SQLite database (default: data/naberius.db)",
    )
    parser.add_argument(
        "--alerts",
        default="data/alerts.db",
        help="Path to output alerts database (default: data/alerts.db)",
    )
    parser.add_argument(
        "--report",
        choices=["json", "html"],
        help="Export a report in the given format",
    )
    parser.add_argument(
        "--output",
        default="reports/report",
        help="Report output path without extension (default: reports/report)",
    )
    parser.add_argument(
        "--api-url",
        default=None,
        help="Naberius REST API base URL (e.g. http://192.168.56.20:5000). When set, --db is ignored.",
    )
    args = parser.parse_args()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    print(f"\n{BOLD}[*] Argus — SSH Log Analyzer{RESET}")

    if args.api_url:
        print(f"    Source    : {args.api_url} (REST API)")
        print(f"    Alerts DB : {args.alerts}")
        print(f"\n[*] Running detection rules...\n")
        alerts = run_analysis_from_api(args.api_url, args.alerts)
    else:
        db_path = Path(args.db)
        if not db_path.exists():
            print(f"[!] Database not found: {db_path}")
            print("    Use --db to point to your naberius.db file.")
            sys.exit(1)
        print(f"    Source DB : {db_path}")
        print(f"    Alerts DB : {args.alerts}")
        print(f"\n[*] Running detection rules...\n")
        alerts = run_analysis(str(db_path), args.alerts)

    print(f"\n{'─' * 60}")
    print(f"[*] {len(alerts)} alert(s) generated\n")

    for a in alerts:
        color  = SEVERITY_COLOR.get(a.severity, "")
        ip_str = f" [{a.ip}]" if a.ip else ""
        print(f"{color}{BOLD}[{a.severity}]{RESET}{ip_str} {a.description}")
        print(f"         MITRE: {a.mitre_technique} — {a.mitre_name}\n")

    if args.report == "json":
        _export_json(alerts, args.output + ".json")
    elif args.report == "html":
        _export_html(alerts, args.output + ".html")


def _export_json(alerts: list[Alert], path: str) -> None:
    data = [
        {
            "rule":            a.rule,
            "severity":        a.severity,
            "description":     a.description,
            "ip":              a.ip,
            "mitre_technique": a.mitre_technique,
            "mitre_name":      a.mitre_name,
            "evidence":        a.evidence,
            "timestamp":       a.timestamp,
        }
        for a in alerts
    ]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] JSON report saved: {path}")


def _export_html(alerts: list[Alert], path: str) -> None:
    badge = {
        "LOW":      '<span style="color:#eab308;font-weight:600">LOW</span>',
        "MEDIUM":   '<span style="color:#f97316;font-weight:600">MEDIUM</span>',
        "HIGH":     '<span style="color:#ef4444;font-weight:600">HIGH</span>',
        "CRITICAL": '<span style="color:#a855f7;font-weight:600">CRITICAL</span>',
    }

    rows = ""
    for a in alerts:
        ip_cell = a.ip or "—"
        rows += f"""
        <tr>
          <td>{badge.get(a.severity, a.severity)}</td>
          <td>{a.rule}</td>
          <td>{html.escape(a.description)}</td>
          <td class="mono">{html.escape(ip_cell)}</td>
          <td class="mono muted">{a.mitre_technique}</td>
          <td class="mono muted">{a.timestamp[:19] if len(a.timestamp) >= 19 else a.timestamp}</td>
        </tr>"""

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Argus — Alert Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #0b0d12;
      color: #e2e8f0;
      font-family: system-ui, sans-serif;
      padding: 48px 32px;
      font-size: 14px;
    }}
    h1   {{ font-size: 22px; font-weight: 600; margin-bottom: 6px; }}
    .meta {{ color: #64748b; font-size: 12px; font-family: monospace; margin-bottom: 36px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      text-align: left; font-size: 11px; text-transform: uppercase;
      letter-spacing: 0.1em; color: #64748b;
      padding: 0 14px 12px; border-bottom: 1px solid #1e2230;
    }}
    td {{ padding: 12px 14px; border-bottom: 1px solid #111318; vertical-align: top; }}
    tr:hover td {{ background: #111318; }}
    .mono  {{ font-family: monospace; font-size: 12px; }}
    .muted {{ color: #64748b; }}
  </style>
</head>
<body>
  <h1>Argus — Alert Report</h1>
  <p class="meta">Generated {generated} &nbsp;·&nbsp; {len(alerts)} alert(s)</p>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>Description</th>
        <th>IP</th>
        <th>MITRE</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody>{rows}
    </tbody>
  </table>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"[+] HTML report saved: {path}")


if __name__ == "__main__":
    main()
