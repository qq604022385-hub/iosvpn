#!/usr/bin/env python3
from pathlib import Path
import argparse, zipfile, hashlib, json, stat, plistlib

def package(app, output):
    app = Path(app).resolve(); output = Path(output).resolve()
    if not app.is_dir() or not app.name.endswith(".app"):
        raise ValueError("A compiled .app directory is required")
    output.parent.mkdir(parents=True, exist_ok=True)
    executables = set()
    for info in [app / "Info.plist", *app.glob("PlugIns/*.appex/Info.plist")]:
        plist = plistlib.loads(info.read_bytes())
        executable = (info.parent / plist["CFBundleExecutable"]).resolve()
        if not executable.is_relative_to(app) or not executable.is_file():
            raise ValueError("Bundle executable missing or outside app")
        executables.add(executable)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as ipa:
        for file in sorted(app.rglob("*")):
            relative = "Payload/" + app.name + "/" + file.relative_to(app).as_posix()
            if file.is_symlink():
                raise ValueError("Unexpected symlink in iOS application")
            if file.is_file():
                info = zipfile.ZipInfo(relative)
                info.create_system = 3
                mode = 0o755 if file.resolve() in executables else (file.stat().st_mode & 0o777)
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                ipa.writestr(info, file.read_bytes())
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".ipa.sha256").write_text(checksum + "  " + output.name + "\n")
    return checksum
if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("app"); parser.add_argument("output")
    args = parser.parse_args(); print("Packaged unsigned IPA:", package(args.app, args.output))