import argparse
import os
import sys
import subprocess
import platform

from .dep_parser import parse_requirements
from .cve_api import query_cve_package
from .analyzer import extract_cve_info
from .output import (
    display_results,
    display_statistics,
    export_to_json,
    export_to_markdown,
)

from pyfiglet import Figlet
from rich.console import Console

console = Console()

# banner
def show_banner():
    f = Figlet(font="graffiti")
    console.print(f"[bold magenta]{f.renderText('BluezCve')}[/bold magenta]")

# scan package
def run_package_scan(deps, quiet=False):
    results = []

    for name, version in deps:
        raw = query_cve_package(name, version)
        cves = extract_cve_info(raw)

        if not quiet:
            display_results(name, version, cves)

        results.append({
            "package": name,
            "version": version,
            "cves": cves,
        })

    if not quiet:
        if any(r["cves"] for r in results):
            display_statistics([c for r in results for c in r["cves"]])
        else:
            console.print("[bold green]✔ No CVEs found[/bold green]")

    return results

# detection kernel

def detect_kernel_release():
    try:
        return platform.release()
    except Exception:
        try:
            return subprocess.check_output(["uname", "-r"], text=True).strip()
        except Exception:
            return None

def main():
    parser = argparse.ArgumentParser(
        prog="BluezCve",
        description=(
            "Uses CPE-first matching against public vulnerability databases.\n"
            "Supports package-based CVE lookup and kernel reference links.\n"
            "Uses CPE-first matching with optional API enrichment.\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # package
    parser.add_argument(
        "-p", "--package",
        metavar="NAME",
        help="Target package name (e.g. openssl, nginx, flask)"
    )
    parser.add_argument(
        "-v", "--version",
        metavar="VERSION",
        help="Package version or kernel version (depends on mode)"
    )
    parser.add_argument(
        "-r", "--requirements",
        metavar="FILE",
        help="Scan CVEs from requirements.txt file"
    )
    parser.add_argument(
        "--freeze",
        action="store_true",
        help="Scan CVEs from current Python environment (pip freeze)"
    )

    # api
    parser.add_argument(
        "--api",
        metavar="API_KEY",
        help=(
            "Optional NVD API key for enrichment\n"
            "• Higher rate limits\n"
            "• Enables EPSS / KEV correlation\n"
            "• Overrides NVD_API_KEY environment variable"
        )
    )

    # output
    parser.add_argument(
        "--json",
        action="store_true",
        help="Export results to JSON file"
    )
    parser.add_argument(
        "--md",
        action="store_true",
        help="Export results to Markdown report"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=".",
        metavar="DIR",
        help="Output directory for exported files (default: current directory)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output (auto-enabled with --json)"
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable ASCII banner"
    )

    # kernel
    parser.add_argument(
        "--linux-kernel",
        action="store_true",
        help="Generate Linux kernel vulnerability reference links"
    )
    parser.add_argument(
        "--win-kernel",
        action="store_true",
        help="Generate Windows kernel vulnerability reference links (requires -v)"
    )
    parser.add_argument(
        "--mac-kernel",
        action="store_true",
        help="Generate macOS XNU kernel vulnerability reference links"
    )

    args = parser.parse_args()
    quiet = args.quiet or args.json

    # use api scann
    if args.api:
        os.environ["NVD_API_KEY"] = args.api

    if not args.no_banner and not quiet:
        show_banner()
    # linux
    if args.linux_kernel:
        from .linux_kernel_check import generate_kernel_check_links

        kernel = args.version or detect_kernel_release()
        if not kernel:
            console.print("[bold red]✘ Failed to detect kernel version[/bold red]")
            sys.exit(1)

        console.rule(f"Linux Kernel {kernel}")
        for e in generate_kernel_check_links(kernel):
            console.print(f"[bold cyan]{e['query']}[/bold cyan]\n  {e['url']}\n")
        sys.exit(0)

    # windows
    if args.win_kernel:
        if not args.version:
            console.print("[bold red]✘ --win-kernel requires -v[/bold red]")
            sys.exit(1)

        from .windows_kernel_check import generate_windows_kernel_links

        console.rule(f"Windows Kernel {args.version}")
        for e in generate_windows_kernel_links(args.version):
            console.print(
                f"[bold cyan]{e['query']}[/bold cyan]\n"
                f"  NVD  : {e['nvd']}\n"
                f"  MSRC : {e['msrc']}\n"
            )
        sys.exit(0)

    # macos
    if args.mac_kernel:
        from .macos_kernel_check import generate_macos_kernel_links

        kernel = args.version or detect_kernel_release()
        if not kernel:
            console.print("[bold red]✘ Failed to detect Darwin version[/bold red]")
            sys.exit(1)

        console.rule(f"macOS Darwin {kernel}")
        for e in generate_macos_kernel_links(kernel):
            console.print(
                f"[bold cyan]{e['query']}[/bold cyan]\n"
                f"  NVD    : {e['nvd']}\n"
                f"  GitHub : {e['github']}\n"
            )
        sys.exit(0)

    #package
    if args.package and args.version:
        results = run_package_scan([(args.package, args.version)], quiet)
    elif args.requirements:
        results = run_package_scan(parse_requirements(args.requirements), quiet)
    elif args.freeze:
        results = run_package_scan(parse_requirements(None), quiet)
    else:
        parser.print_help()
        sys.exit(0)

    if args.json or args.md:
        os.makedirs(args.output_dir, exist_ok=True)

    if args.json:
        export_to_json(results, f"{args.output_dir}/bluezcve.json", quiet)
    if args.md:
        export_to_markdown(results, f"{args.output_dir}/bluezcve.md", quiet)

    sys.exit(1 if any(r["cves"] for r in results) else 0)


if __name__ == "__main__":
    main()
