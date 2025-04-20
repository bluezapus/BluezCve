import re
import subprocess
import os


def parse_requirements(path="requirements.txt"):
    requirements = []

    if os.path.exists(path):
        with open(path) as f:
            lines = f.readlines()
    else:
        print("[yellow]requirements.txt not found, using pip freeze...[/yellow]")
        try:
            lines = subprocess.check_output(["pip", "freeze"], text=True).splitlines()
        except subprocess.CalledProcessError:
            print("[red]Failed to run pip freeze[/red]")
            return []

    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and "==" in line:
            pkg, ver = line.split("==", 1)
            requirements.append((pkg.strip(), ver.strip()))

    return requirements
