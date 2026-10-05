"""depaudit command-line entry point.

    depaudit                scan the current directory
    depaudit path           scan a directory
    depaudit --min high     only high and critical findings
    depaudit --json         machine-readable output

Exit status: 0 clean, 1 findings at/above --fail-on, 2 on error.
"""

from __future__ import annotations

import json as jsonlib
import sys

import click
from rich.console import Console
from rich.text import Text

from depaudit import __version__
from depaudit.audit import SEVERITY_ORDER, audit

SEVERITY_STYLE = {"critical": "bold white on red", "high": "bold red",
                  "medium": "bold yellow", "low": "cyan"}
_LEVELS = ("low", "medium", "high", "critical")


@click.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--min", "min_sev", type=click.Choice(_LEVELS), default="low")
@click.option("--fail-on", type=click.Choice(_LEVELS), default="high")
@click.option("--json", "json_out", is_flag=True)
@click.option("--no-color", is_flag=True)
@click.version_option(__version__, package_name="depaudit", prog_name="depaudit")
def main(path, min_sev, json_out, fail_on, no_color):
    """Find supply-chain risks in npm and pip dependency files."""
    console = Console(no_color=no_color, highlight=False)
    try:
        findings = audit(path)
    except Exception as exc:  # noqa: BLE001
        click.echo(f"depaudit: error while scanning: {exc}", err=True)
        sys.exit(2)

    shown = [f for f in findings if SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[min_sev]]
    worst = min((SEVERITY_ORDER[f.severity] for f in findings), default=99)
    failed = worst <= SEVERITY_ORDER[fail_on]

    if json_out:
        click.echo(jsonlib.dumps(
            {"version": __version__, "findings": [f.to_dict() for f in shown]}, indent=2))
    else:
        _report(console, shown, findings)
    sys.exit(1 if failed else 0)


def _report(console, shown, all_findings):
    console.print(Text("depaudit ", style="bold").append(__version__, style="dim"))
    by_path: dict[str, list] = {}
    for f in shown:
        by_path.setdefault(f.path, []).append(f)
    for path in sorted(by_path):
        console.print()
        console.print(Text(path, style="bold"))
        for f in by_path[path]:
            tag = f" {f.severity.upper()} "
            head = Text("  ").append(tag, style=SEVERITY_STYLE[f.severity])
            head.append("  ").append(f.title).append(f"  {f.check}", style="dim")
            console.print(head)
            if f.package:
                console.print(Text("      package: " + f.package, style="dim"))
            for line in _wrap(f.description, 84):
                console.print(Text("      " + line, style="dim"))
    console.print()
    if not all_findings:
        console.print(Text("clean, no dependency risks found", style="green"))
        return
    counts = {lvl: 0 for lvl in _LEVELS}
    for f in all_findings:
        counts[f.severity] += 1
    summary = "  ".join(f"{counts[l]} {l}" for l in reversed(_LEVELS) if counts[l])
    worst = min(all_findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
    console.print(Text(summary, style=SEVERITY_STYLE[worst]))


def _wrap(text, width):
    words, lines, line = text.split(), [], ""
    for w in words:
        if line and len(line) + 1 + len(w) > width:
            lines.append(line); line = ""
        line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


if __name__ == "__main__":
    main()
