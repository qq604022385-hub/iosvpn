#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, tarfile, urllib.request, shutil
IOS = Path(__file__).resolve().parents[1]
lock = json.loads((IOS / "dependencies.lock.json").read_text(encoding="utf8"))["openssl"]
cache = IOS / "build/downloads"; cache.mkdir(parents=True, exist_ok=True)
archive = cache / ("openssl-" + lock["version"] + ".tar.gz")
bundled = IOS.parent / "vendor" / archive.name
if not archive.exists() and bundled.is_file():
    shutil.copyfile(bundled, archive)
if not archive.exists():
    with urllib.request.urlopen(lock["url"], timeout=90) as response:
        archive.write_bytes(response.read())
if hashlib.sha256(archive.read_bytes()).hexdigest() != lock["sha256"]:
    raise SystemExit("OpenSSL archive SHA256 mismatch")
destination = IOS / "build/openssl-src"
if destination.exists():
    raise SystemExit("OpenSSL source already exists; use a fresh build directory")
with tarfile.open(archive) as tar:
    tar.extractall(destination, filter="data")
print(destination / ("openssl-" + lock["version"]))