#!/usr/bin/env python3
"""Create and patch an isolated strongSwan build tree. Never modify ../src."""
from pathlib import Path
import argparse, shutil, re, tarfile, hashlib
ROOT = Path(__file__).resolve().parents[2]
IOS = ROOT / "ios"
SKIP = {".git", ".libs", ".deps", "autom4te.cache", "__pycache__"}
TOP_FILES = ["configure.ac", "Makefile.am", "autogen.sh", "COPYING", "AUTHORS", "INSTALL", "NEWS", "README", "ChangeLog", "Doxyfile.in", "Android.common.mk.in"]
def normalize_tree(directory):
    text_suffixes = {".sh", ".am", ".ac", ".m4", ".in", ".mk", ".pl", ".py", ".c", ".h"}
    for file in Path(directory).rglob("*"):
        if not file.is_file():
            continue
        raw = file.read_bytes()
        # git-version and other executable scripts have no extension. Detect
        # their shebang, while leaving binary data and ordinary files intact.
        is_source_text = file.suffix in text_suffixes or raw.startswith(b"#!")
        if is_source_text and b"\r\n" in raw and b"\0" not in raw:
            file.write_bytes(raw.replace(b"\r\n", b"\n"))
def copy_tree(destination):
    destination = Path(destination).resolve()
    allowed = (IOS / "build").resolve()
    if not destination.is_relative_to(allowed) or destination == allowed:
        raise ValueError("Build destination must be a subdirectory of ios/build")
    if destination.exists():
        raise FileExistsError(f"Use a fresh build directory: {destination}")
    destination.mkdir(parents=True)
    if not (ROOT / "src").is_dir():
        archive = ROOT / "vendor/strongswan-source.tar.gz"
        expected = (ROOT / "vendor/strongswan-source.sha256").read_text(encoding="utf8").strip()
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise ValueError("Vendored strongSwan source SHA256 mismatch")
        with tarfile.open(archive) as tar:
            tar.extractall(destination, filter="data")
        if not (destination / "configure.ac").is_file():
            raise ValueError("Invalid vendored source layout")
        normalize_tree(destination)
        return destination
    for name in TOP_FILES:
        shutil.copy2(ROOT / name, destination / name)
    # Configure generates Makefiles throughout the source tree, even for disabled targets.
    for name in ["src", "m4", "conf", "init", "man", "scripts", "testing", "fuzz"]:
        shutil.copytree(ROOT / name, destination / name,
            ignore=shutil.ignore_patterns(*SKIP, "*.o", "*.lo", "*.la", "Makefile", "Makefile.in", "*.exe", "*.apk", "*.so", "*.a", "*.dll", "build", ".gradle"))
    normalize_tree(destination)
    return destination

def patch(destination):
    destination = Path(destination)
    replacements = {
        "tun_device_ios.c": "src/libstrongswan/networking/tun_device.c",
        "process_ios.c": "src/libstrongswan/utils/process.c",
        "capabilities_ios.c": "src/libstrongswan/utils/capabilities.c",
        "xauth_generic_ios.c": "src/libcharon/plugins/xauth_generic/xauth_generic.c",
    }
    for source, target in replacements.items():
        shutil.copy2(IOS / "Native" / source, destination / target)
    p = destination / "src/libcharon/plugins/kernel_libipsec/kernel_libipsec_plugin.c"
    text = p.read_text(encoding="utf8")
    pattern = r'\tif \(!lib->caps->check\(lib->caps, CAP_NET_ADMIN\)\)\n\t\{.*?\n\t\}\n'
    text, count = re.subn(pattern, '\t/* iOS: public Packet Flow adapter requires no privileged TUN creation. */\n', text, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError("strongSwan kernel-libipsec capability check changed")
    p.write_text(text, encoding="utf8")
    p = destination / "src/libcharon/plugins/vici/vici_cred.c"
    text = p.read_text(encoding="utf8")
    needle = 'else if (strcaseeq(str, "ntlm"))'
    if needle not in text:
        raise RuntimeError("strongSwan VICI shared-key parser changed")
    text = text.replace(needle, 'else if (strcaseeq(str, "pin"))\n\t{\n\t\ttype = SHARED_PIN;\n\t}\n\t' + needle, 1)
    p.write_text(text, encoding="utf8")
    # Do not retain VICI message payloads containing credentials after disposal.
    p = destination / "src/libcharon/plugins/vici/vici_message.c"
    text = p.read_text(encoding="utf8")
    needle = 'if (this->cleanup)\n\t{\n\t\tfree(this->encoding.ptr);'
    if needle in text:
        text = text.replace(needle, 'if (this->cleanup)\n\t{\n\t\tmemwipe(this->encoding.ptr, this->encoding.len);\n\t\tfree(this->encoding.ptr);', 1)
    elif 'chunk_clear(&this->encoding);' not in text:
        raise RuntimeError("strongSwan VICI cleanup changed")
    p.write_text(text, encoding="utf8")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("destination"); args = parser.parse_args()
    patch(copy_tree(args.destination))
    print("Prepared isolated strongSwan source:", args.destination)