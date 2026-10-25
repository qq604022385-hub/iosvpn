#!/usr/bin/env python3
"""Reject shell scripts that cannot be parsed reliably by macOS Bash."""
from pathlib import Path
import argparse

SCRIPTS = Path(__file__).resolve().parent


def check_shell_scripts(directory):
    directory = Path(directory)
    scripts = sorted(directory.rglob("*.sh"))
    if not scripts:
        raise ValueError(f"No shell scripts found in {directory}")
    for script in scripts:
        raw = script.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError(f"{script}: UTF-8 BOM detected; save as UTF-8 without BOM")
        if b"\r" in raw:
            line = raw[:raw.index(b"\r")].count(b"\n") + 1
            raise ValueError(f"{script}:{line}: CR/CRLF detected; save with LF line endings")
    return len(scripts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=SCRIPTS)
    args = parser.parse_args()
    try:
        count = check_shell_scripts(args.directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")
    print(f"PASS: {count} shell scripts use LF with no UTF-8 BOM")


if __name__ == "__main__":
    main()
