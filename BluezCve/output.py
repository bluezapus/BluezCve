from rich import print
from rich.panel import Panel
from rich.console import Console
from collections import Counter
from rich.text import Text
import json

console = Console()


def severity_color(severity):
    severity = severity.upper()
    return {
        "CRITICAL": "bold red",
        "HIGH": "bold dark_orange",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }.get(severity, "dim")


def display_results(package, version, cves):
    header = Text(f"{package} {version}", style="bold blue")
    console.rule(header, style="blue")

    if not cves:
        console.print("[bold blue][✔] No CVEs found[/bold blue]")
        return

    for cve in cves:
        cve_id = cve.get("id", "UNKNOWN")
        desc = cve.get("desc", "No description available.")
        severity = cve.get("severity", "UNKNOWN").upper()
        score = cve.get("score", "N/A")
        link = cve.get("link", "#")

        # Tetap warnai level severity saja
        severity_styled = (
            f"[{severity_color(severity)}]{severity}[/]"
            if severity != "UNKNOWN"
            else "[dim]UNKNOWN[/dim]"
        )

        body = Text.from_markup(
            f"[blue][bold]Level:[/] {severity_styled}\n"
            f"[bold]Score:[/] {score}\n"
            f"[italic]{desc}[/]\n"
            f"🔗 {link}[/blue]"
        )

        title_text = Text(f"[!] {cve_id}", style="bold blue")

        panel = Panel.fit(
            body,
            title=title_text,
            border_style="blue",
        )
        console.print(panel)


from collections import Counter


def display_statistics(all_cves):
    severities = [cve.get("severity", "UNKNOWN").upper() for cve in all_cves]
    count = Counter(severities)

    emoji = {
        "CRITICAL": "[!]",
        "HIGH": "[!]",
        "MEDIUM": "[!]",
        "LOW": "[!]",
        "UNKNOWN": "[?]",
    }

    print("\n[bold cyan][+] CVE Statistics:[/bold cyan]")
    print(f"- Total CVEs: [bold]{sum(count.values())}[/bold]")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if count[level]:
            icon = emoji.get(level, "")
            print(f"- {icon} {level.title()}: {count[level]}")


def main():
    results = []
    all_cves = []

    dependencies = parse_requirements()

    for pkg, ver in dependencies:
        cves = analyze_package(pkg, ver)
        results.append(
            {
                "package": pkg,
                "version": ver,
                "cves": cves,
            }
        )
        display_results(pkg, ver, cves)
        all_cves.extend(cves)

    export_to_json(results)
    export_to_markdown(results)

    if all_cves:
        display_statistics(all_cves)
    else:
        print("\n[bold blue][✔] CVE bot found![/bold blue]")


if __name__ == "__main__":
    main()


def export_to_json(results, filename="vuln_report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[bold blue][✔] JSON report saved to {filename}[/bold blue]")


def export_to_markdown(results, filename="vuln_report.md"):
    with open(filename, "w") as f:
        f.write("# Vulnerability Report\n\n")
        for entry in results:
            pkg = entry["package"]
            version = entry["version"]
            cves = entry["cves"]
            f.write(f"## {pkg} {version}\n\n")
            if not cves:
                f.write("- No CVEs found.\n\n")
            else:
                for cve in cves:
                    cve_id = cve.get("id", "Unknown CVE")
                    severity = cve.get("severity", "UNKNOWN")
                    score = cve.get("score", "N/A")
                    desc = cve.get("desc", "No description")
                    link = cve.get("link", "#")

                    f.write(f"### {cve_id} ({severity})\n")
                    f.write(f"- **Score:** {score}\n")
                    f.write(f"- **Description:** {desc}\n")
                    f.write(f"- **Link:** [{cve_id}]({link})\n\n")
    print(f"[bold blue][✔] Markdown report saved to {filename}[/bold blue]")
