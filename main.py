# main.py
# entry point for the Cloudhunter CLI
# using Click because it is much cleaner than argparse for this kind of tool
# the consent flag is required by my ethics section in the thesis
# the idea is the same as Metasploit's disclaimer, tool refuses to run without it

import sys
import csv
from pathlib import Path
import webbrowser
import click
from engine.aws_connector import scan_aws, scan_aws_demo
from engine.report import generate_html_report

# shown when user provides the consent flag for a live scan
# based on the Computer Misuse Act 1990 section in my literature review
_LEGAL_NOTICE = """
╔══════════════════════════════════════════════════════════════════╗
║               CLOUDHUNTER — LEGAL NOTICE                        ║
╠══════════════════════════════════════════════════════════════════╣
║  By continuing you confirm that:                                 ║
║   • You have written authorisation to scan the target account    ║
║   • This tool will only make READ-ONLY API calls                 ║
║   • No data will be exfiltrated outside your local machine       ║
║   • Unauthorised use may violate the Computer Misuse Act 1990    ║
╚══════════════════════════════════════════════════════════════════╝
"""

# shown instead when running in demo mode
# makes it obvious no real AWS calls are happening
_DEMO_NOTICE = """
╔══════════════════════════════════════════════════════════════════╗
║               CLOUDHUNTER — DEMO MODE                           ║
╠══════════════════════════════════════════════════════════════════╣
║  Running with synthetic findings — no AWS API calls are made.   ║
║  CVSS scoring and MITRE mapping are real (same code path).      ║
║  Use without --demo to scan a live AWS account.                 ║
╚══════════════════════════════════════════════════════════════════╝
"""


@click.group(help="Cloudhunter CLI — cloud misconfiguration scanner")
def cli():
    pass


@cli.command("scan")
@click.option(
    "--provider",
    type=click.Choice(["aws", "azure"]),
    required=True,
    help="Cloud provider to scan.",
)
@click.option(
    "--output",
    type=click.Path(),
    default="results.csv",
    show_default=True,
    help="Path for the CSV output file.",
)
@click.option(
    # ethics requirement - user has to type this explicitly every time
    # not just a one time checkbox, they actively confirm permission each run
    "--yes-i-have-authorisation",
    "authorised",
    is_flag=True,
    default=False,
    help="Confirm you have written authorisation to scan this account (required).",
)
@click.option(
    # demo mode uses fake findings so you can run the tool without any AWS credentials
    # CVSS and MITRE still run through the real code, only the boto3 calls are skipped
    "--demo",
    is_flag=True,
    default=False,
    help="Run with synthetic findings instead of live AWS calls. No credentials needed.",
)
def scan(provider: str, output: str, authorised: bool, demo: bool):
    """Run a security scan for the selected cloud provider and export results to CSV."""

    # consent gate - if the flag is missing we show how to add it and exit
    # we never run without consent, not even in demo mode
    if not authorised:
        click.echo(
            "[!] You must confirm you have authorisation before scanning.\n"
            "    Add the flag: --yes-i-have-authorisation\n\n"
            "    Live scan:\n"
            "      python main.py scan --provider aws --yes-i-have-authorisation\n\n"
            "    Demo mode (no credentials needed):\n"
            "      python main.py scan --provider aws --demo --yes-i-have-authorisation\n",
            err=True,
        )
        sys.exit(1)

    if provider == "aws":

        if demo:
            # demo mode - fake data, no boto3 API calls at all
            click.echo(_DEMO_NOTICE)
            click.echo("[*] Loading synthetic AWS findings...")
            click.echo(f"[*] Results will be saved to: {output}")
            count = scan_aws_demo(output)
            click.echo(f"\n[+] Demo scan complete — {count} finding(s) written to {output}")
        else:
            # live mode - real boto3 calls to the actual AWS account
            click.echo(_LEGAL_NOTICE)
            click.echo("[*] Starting live AWS scan...")
            click.echo(f"[*] Results will be saved to: {output}")
            count = scan_aws(output)
            click.echo(f"\n[+] AWS scan complete — {count} finding(s) written to {output}")

        if count > 0:
            _print_summary(output)
            # generate html report next to the csv
            html_path = str(Path(output).with_suffix(".html"))
            mode = "demo" if demo else "live"
            generate_html_report(output, html_path, mode=mode)
            click.echo(f"[*] HTML report saved to: {html_path}")
            click.echo(f"[*] Open it with: open {html_path}")
        return

    # azure is Phase 2, leaving the stub here so the CLI is ready when i add it
    click.echo(
        "[!] Azure scanning is in progress — expected in Phase 2 (post-May 2026).\n"
        "    For now, use: --provider aws",
        err=True,
    )
    sys.exit(2)


def _print_summary(output_path: str):
    # reads the CSV back and prints a clean table in the terminal
    # much easier to read during a demo than opening the file
    with open(output_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        return

    # column widths - fixed so the table looks neat
    w_resource = 45
    w_check    = 20
    w_severity = 10
    w_cvss     = 6
    w_mitre    = 12

    top    = f"┌{'─'*w_resource}┬{'─'*w_check}┬{'─'*w_severity}┬{'─'*w_cvss}┬{'─'*w_mitre}┐"
    header = f"│{'Resource'.ljust(w_resource)}│{'Check'.ljust(w_check)}│{'Severity'.ljust(w_severity)}│{'CVSS'.ljust(w_cvss)}│{'MITRE'.ljust(w_mitre)}│"
    div    = f"├{'─'*w_resource}┼{'─'*w_check}┼{'─'*w_severity}┼{'─'*w_cvss}┼{'─'*w_mitre}┤"
    bot    = f"└{'─'*w_resource}┴{'─'*w_check}┴{'─'*w_severity}┴{'─'*w_cvss}┴{'─'*w_mitre}┘"

    click.echo("\n" + top)
    click.echo(header)
    click.echo(div)

    for row in rows:
        resource = row["resource_id"][:w_resource].ljust(w_resource)
        check    = row["check_id"][:w_check].ljust(w_check)
        severity = row["severity"][:w_severity].ljust(w_severity)
        cvss     = str(row["cvss_score"])[:w_cvss].ljust(w_cvss)
        mitre    = row["mitre_id"][:w_mitre].ljust(w_mitre)
        click.echo(f"│{resource}│{check}│{severity}│{cvss}│{mitre}│")

    click.echo(bot)

    highs   = sum(1 for r in rows if r["severity"] == "high")
    mediums = sum(1 for r in rows if r["severity"] == "medium")
    click.echo(f"\n[!] {highs} high  |  {mediums} medium  |  {len(rows)} total findings\n")


if __name__ == "__main__":
    cli()