from .dep_parser import parse_requirements
from .cve_api import query_cve
from .analyzer import extract_cve_info
from .output import (
    display_results,
    export_to_json,
    export_to_markdown,
    display_statistics,
)
from pyfiglet import Figlet
from rich.console import Console

console = Console()


def show_banner():
    f = Figlet(font="slant")
    ascii_banner = f.renderText("BluezCve")
    console.print(f"[bold magenta]{ascii_banner}[/bold magenta]")


def run_scan(deps):
    all_results = []
    for name, version in deps:
        cve_raw = query_cve(name, version)
        cve_info = extract_cve_info(cve_raw) if cve_raw else []
        display_results(name, version, cve_info)
        all_results.append({"package": name, "version": version, "cves": cve_info})

    export_to_json(all_results)
    export_to_markdown(all_results)

    if any(pkg["cves"] for pkg in all_results):
        all_cves = [cve for pkg in all_results for cve in pkg["cves"]]
        display_statistics(all_cves)
    else:
        console.print("\n[bold green]✔ Tidak ada CVE ditemukan![/bold green]")


def main():
    show_banner()

    while True:
        console.print("\n[bold cyan]Select Option:[/bold cyan]")
        console.print("[1] Scan file requirements.txt / pip freeze")
        console.print("[2] Check manual package")
        console.print("[3] Exit")
        choice = input("Enter the choice [1/2/3] >> ").strip()

        if choice == "1":
            path = input("File Path .txt >> ").strip()
            deps = parse_requirements(path or "requirements.txt")
            run_scan(deps)

        elif choice == "2":
            name = input("Package name >> ").strip()
            version = input("Package version >> ").strip()
            run_scan([(name, version)])

        elif choice == "3":
            console.print("[bold red][-] Exit...[/bold red]")
            break

        else:
            console.print("[red][X] Invalid choice! Try again.[/red]")


if __name__ == "__main__":
    main()
