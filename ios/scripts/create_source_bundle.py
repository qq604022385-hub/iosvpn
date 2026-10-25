#!/usr/bin/env python3
"""Build an uploadable standalone source tree, excluding Windows binaries and credentials."""
from pathlib import Path
import hashlib, json, tarfile, tempfile, zipfile, argparse
from prepare_source import copy_tree, IOS, ROOT
from check_shell_scripts import check_shell_scripts

skip = {"build", ".build", ".swiftpm", "artifacts", "__pycache__", "FortiOneTap.xcodeproj"}
source_directories = {"App", "Core", "Native", "NativeTests", "scripts", "Shared", "Tests", "Tunnel", "verification"}
parser=argparse.ArgumentParser();parser.add_argument("--output-name",default="FortiOneTap-iOS-source.zip");args=parser.parse_args()
if Path(args.output_name).name!=args.output_name or not args.output_name.endswith(".zip"):raise ValueError("Expected plain ZIP filename")
output = IOS / "artifacts" / args.output_name
check_shell_scripts(IOS / "scripts")
output.parent.mkdir(parents=True, exist_ok=True)
(IOS / "build").mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix="source-package-", dir=IOS / "build") as temp:
    temp = Path(temp).resolve()
    assert temp.is_relative_to((IOS / "build").resolve())
    source = copy_tree(temp / "strongswan")
    vendor = temp / "strongswan-source.tar.gz"
    with tarfile.open(vendor, "w:gz") as archive:
        for file in sorted(source.rglob("*")):
            if file.is_file():
                info = archive.gettarinfo(file, arcname=file.relative_to(source).as_posix())
                info.uid = info.gid = 0; info.uname = info.gname = ""
                info.mode = 0o755 if file.read_bytes().startswith(b"#!") else 0o644
                with file.open("rb") as handle: archive.addfile(info, handle)
    source_hash = hashlib.sha256(vendor.read_bytes()).hexdigest()
    dependency_lock = json.loads((IOS / "dependencies.lock.json").read_text())["openssl"]
    openssl_archive = IOS / "build/downloads" / ("openssl-" + dependency_lock["version"] + ".tar.gz")
    assert hashlib.sha256(openssl_archive.read_bytes()).hexdigest() == dependency_lock["sha256"]
    included = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for file in sorted(IOS.rglob("*")):
            parts = file.relative_to(IOS).parts
            # Ignore extracted copies of previous upload packages and other
            # unrelated directories; only ship this project's source roots.
            if len(parts) > 1 and parts[0] not in source_directories:
                continue
            if file.is_file() and not any(s in skip for s in parts) and file.suffix not in {".p12", ".mobileprovision", ".ipa", ".dpapi"}:
                relative = "ios/" + file.relative_to(IOS).as_posix()
                bundle.write(file, relative); included.append(relative)
        bundle.write(ROOT / ".github/workflows/ios-ipa.yml", ".github/workflows/ios-ipa.yml")
        bundle.write(ROOT / ".gitattributes", ".gitattributes")
        bundle.write(ROOT / ".gitignore", ".gitignore")
        bundle.write(vendor, "vendor/strongswan-source.tar.gz")
        bundle.write(openssl_archive, "vendor/" + openssl_archive.name)
        bundle.writestr("vendor/strongswan-source.sha256", source_hash + "\n")
        for file in ["COPYING", "AUTHORS", "LICENSE", "NETWORK-THROUGHPUT-1.3.2.md", "NETWORK-MEMORY-1.3.3.md", "NETWORK-IOS-1.3.4.md", "NETWORK-IOS-1.3.5.md", "NETWORK-IOS-1.4.0.md", "NETWORK-IOS-1.4.1.md", "AUTO-TOKEN-1.4.2.md", "RECONNECT-1.4.3.md", "WIFI-CLIENT-1.4.8.md"]:
            if (ROOT / file).is_file(): bundle.write(ROOT / file, file)
        bundle.write(IOS / "README.md", "README.md")
        bundle.writestr("SOURCE-MANIFEST.json", json.dumps({"source": "Independent Forti strongSwan 6.1.0 and Hillstone SCVPN iOS client", "strongswan_source_sha256": source_hash, "ios_files": included, "build": "GitHub Actions macos-15", "signing": "unsigned"}, indent=2))
checksum = hashlib.sha256(output.read_bytes()).hexdigest()
output.with_suffix(".zip.sha256").write_text(checksum + "  " + output.name + "\n")
print(json.dumps({"source_bundle": str(output), "bytes": output.stat().st_size, "sha256": checksum}, ensure_ascii=False, indent=2))
