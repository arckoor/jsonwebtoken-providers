from pathlib import Path
import subprocess
import os
import json
import textwrap
import argparse


UPSTREAM = Path("upstream").resolve()
PROVIDERS = Path("providers").resolve()


def cargo_add(*args, cwd):
    subprocess.run(
        ["cargo", "add", *args],
        cwd=cwd,
        check=True,
    )


def get_package_version(package: str, cwd) -> str:
    print("Getting package version from provider")
    cmd = ["cargo", "metadata", "--format-version", "1"]
    data = subprocess.check_output(cmd, cwd=cwd)
    metadata = json.loads(data)

    for pkg in metadata["packages"]:
        if pkg["name"] == package:
            return f"{package}@{pkg['version']}"

    raise ValueError(f"Package {package} not found")


def patch_crate_usage(file: Path):
    print(f"Patching crate usage for {file}")
    text = file.read_text()
    text = text.replace("jsonwebtoken::", "crate::")
    file.write_text(text)


def patch_provider_mod():
    print("Patching provider mod.rs")
    path = UPSTREAM / "src" / "crypto" / "provider" / "mod.rs"
    text = path.read_text()
    text += textwrap.dedent("""
        #[ctor::ctor(unsafe)]
        fn init() {
            DEFAULT_PROVIDER.install_default().unwrap();
        }
        """)
    path.write_text(text)


def patch_crypto_mod():
    print("Patching crypto mod.rs")
    path = UPSTREAM / "src" / "crypto" / "mod.rs"
    lines = path.read_text().splitlines()
    idx = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("//!"):
            idx += 1
        elif stripped == "":
            idx += 1
        else:
            break

    lines.insert(idx, "pub mod provider;")
    path.write_text("\n".join(lines))


def main(package: str, crate: str):
    subprocess.run(
        ["cp", "-r", f"{PROVIDERS}/{crate}/src", f"{UPSTREAM}/src/crypto/provider"],
        check=True,
    )
    subprocess.run(
        [
            "mv",
            f"{UPSTREAM}/src/crypto/provider/lib.rs",
            f"{UPSTREAM}/src/crypto/provider/mod.rs",
        ],
        check=True,
    )
    for file in os.listdir(f"{UPSTREAM}/src/crypto/provider/"):
        patch_crate_usage(UPSTREAM / "src" / "crypto" / "provider" / file)
    patch_provider_mod()
    patch_crypto_mod()
    package_version = get_package_version(package, PROVIDERS / crate)
    cargo_add(package_version, cwd=UPSTREAM)
    cargo_add("ctor", cwd=UPSTREAM)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--package")
    parser.add_argument("--crate")
    args = parser.parse_args()
    main(args.package, args.crate)
