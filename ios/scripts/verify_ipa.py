#!/usr/bin/env python3
from pathlib import Path
import argparse, hashlib, json, plistlib, struct, zipfile

def macho_device(binary):
    if len(binary) < 32: raise ValueError("Executable is too small")
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<8I", binary)
    if magic != 0xfeedfacf or cpu != 0x100000c or filetype != 2:
        raise ValueError("Expected an arm64 Mach-O device executable")
    offset = 32; ios = False
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", binary, offset)
        if size < 8 or offset + size > len(binary): raise ValueError("Malformed Mach-O command")
        if command == 0x32: ios |= struct.unpack_from("<I", binary, offset + 8)[0] == 2
        if command == 0x25: ios = True # Legacy LC_VERSION_MIN_IPHONEOS
        offset += size
    if not ios: raise ValueError("Missing device iOS platform load command")

def verify(path):
    with zipfile.ZipFile(path) as ipa:
        if ipa.testzip() is not None: raise ValueError("Corrupt IPA archive")
        names = ipa.namelist()
        if any(n.startswith("/") or ".." in n.split("/") for n in names): raise ValueError("Unsafe IPA path")
        app_infos = [n for n in names if n.startswith("Payload/") and n.count("/") == 2 and n.endswith(".app/Info.plist")]
        if len(app_infos) != 1: raise ValueError("Expected exactly one Payload application")
        app_root = app_infos[0].removesuffix("Info.plist")
        app = plistlib.loads(ipa.read(app_infos[0]))
        extensions = [n for n in names if n.startswith(app_root + "PlugIns/") and n.endswith(".appex/Info.plist")]
        if len(extensions) != 1: raise ValueError("Expected the embedded VPN extension")
        extension = plistlib.loads(ipa.read(extensions[0])); extension_root = extensions[0].removesuffix("Info.plist")
        if extension["CFBundleIdentifier"] != app["CFBundleIdentifier"] + ".Tunnel": raise ValueError("Mismatched extension bundle identifier")
        ne = extension["NSExtension"]
        if ne["NSExtensionPointIdentifier"] != "com.apple.networkextension.packet-tunnel": raise ValueError("Wrong extension type")
        if not ne["NSExtensionPrincipalClass"].endswith(".PacketTunnelProvider"): raise ValueError("Wrong provider principal class")
        for root, info in [(app_root, app), (extension_root, extension)]:
            executable = root + info["CFBundleExecutable"]
            macho_device(ipa.read(executable))
            if ipa.getinfo(executable).external_attr >> 16 & 0o111 == 0: raise ValueError("Missing executable permission")
        resources = [n for n in names if n.endswith("/cn-ipv4.txt")]
        if not resources: raise ValueError("Missing domestic routing rules")
        lock = json.loads((Path(__file__).resolve().parents[1] / "dependencies.lock.json").read_text(encoding="utf8"))["cn_ipv4"]
        for resource in resources:
            if hashlib.sha256(ipa.read(resource)).hexdigest() != lock["sha256"]: raise ValueError("Route snapshot mismatch")
        if any(n.endswith(("settings.dpapi", ".p12", ".mobileprovision")) for n in names): raise ValueError("Unexpected credential/signing material in unsigned IPA")
        return {"bundle": app["CFBundleIdentifier"], "extension": extension["CFBundleIdentifier"], "architecture": "arm64", "platform": "iOS device", "signing": "unsigned; must sign app and VPN extension before installation"}
if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("ipa"); args = p.parse_args()
    result = verify(args.ipa); print(json.dumps(result, ensure_ascii=False, indent=2))
    Path(args.ipa).with_suffix(".verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf8")