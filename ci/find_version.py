import subprocess
import json
from pathlib import Path
import sys

PROVIDERS = Path("providers").resolve()


def get_package_version(package: str, cwd) -> str:
    print(f"Getting package version for pkg {package}", file=sys.stderr)
    cmd = ["cargo", "metadata", "--format-version", "1"]
    data = subprocess.check_output(cmd, cwd=cwd)
    metadata = json.loads(data)

    for pkg in metadata["packages"]:
        if pkg["name"] == package:
            return f"{pkg['version']}"

    raise ValueError(f"Package {package} not found")


if __name__ == "__main__":
    version = get_package_version("jsonwebtoken", PROVIDERS)
    print(f"Got jsonwebtoken version {version}", file=sys.stderr)
    print(version)
