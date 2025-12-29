from rich import print
from rich.panel import Panel
from rich.console import Console
from collections import Counter
from rich.text import Text
import json

console = Console()


def severity_color(severity):
    return {
        "CRITICAL": "bold red",
        "HIGH": "bold dark_orange",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }.get(severity.upper(), "dim")


def display_results(package, version, cves):
    header = Text(f"{package} {version}", style="bold blue")
    console.rule(header, style="blue")

    if not cves:
        console.print("[bold blue][✔] No CVEs found[/bold blue]")
        return

    for cve in cves:
        panel = Panel.fit(
            Text.from_markup(
                f"[bold]Severity:[/] [{severity_color(cve['severity'])}]{cve['severity']}[/]\n"
                f"[bold]Score:[/] {cve['score']}\n"
                f"[italic]{cve['desc']}[/]\n"
                f"{cve['link']}"
            ),
            title=f"[!] {cve['id']}",
            border_style="blue",
        )
        console.print(panel)


def display_statistics(all_cves):
    count = Counter(cve["severity"].upper() for cve in all_cves)
    print("\n[bold cyan][+] CVE Statistics:[/bold cyan]")
    print(f"- Total CVEs: [bold]{sum(count.values())}[/bold]")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if count.get(sev):
            print(f"- {sev}: {count[sev]}")


def export_to_json(results, filename, quiet=False):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    if not quiet:
        print(f"[bold blue][✔] JSON report saved: {filename}[/bold blue]")


def export_to_markdown(results, filename, quiet=False):
    with open(filename, "w") as f:
        f.write("# Vulnerability Report\n\n")
        for entry in results:
            f.write(f"## {entry['package']} {entry['version']}\n\n")
            if not entry["cves"]:
                f.write("- No CVEs found\n\n")
                continue
            for cve in entry["cves"]:
                f.write(
                    f"### {cve['id']} ({cve['severity']})\n"
                    f"- Score: {cve['score']}\n"
                    f"- Description: {cve['desc']}\n"
                    f"- Link: {cve['link']}\n\n"
                )
    if not quiet:
        print(f"[bold blue][✔] Markdown report saved: {filename}[/bold blue]")
