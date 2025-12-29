import os
import subprocess


def parse_requirements(path):
    """
    Parse dependencies from:
    - requirements file (if path is provided)
    - active environment via pip freeze (if path is None)
    """

    deps = []

    # MODE 1: requirements file
    if path is not None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Requirements file not found: {path}")

        with open(path, "r") as f:
            lines = f.readlines()

    # MODE 2: pip freeze
    else:
        try:
            result = subprocess.run(
                ["pip", "freeze"],
                capture_output=True,
                text=True,
                check=True,
            )
            lines = result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Failed to run pip freeze") from e

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "==" in line:
            name, version = line.split("==", 1)
            deps.append((name.strip(), version.strip()))

    return deps
