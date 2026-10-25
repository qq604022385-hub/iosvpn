#!/usr/bin/env python3
"""Type-check app and extension independently against the real iPhone SDK.
Does not create substitute APIs, resource accessors, native engines, or IPA files.
"""
from pathlib import Path
import subprocess, sys
IOS = Path(__file__).resolve().parents[1]
logs = IOS / 'build/logs'; logs.mkdir(parents=True, exist_ok=True)
modules = IOS / 'build/ios-typecheck'; modules.mkdir(parents=True, exist_ok=True)

def xcrun(*arguments):
    return subprocess.check_output(['xcrun', '--sdk', 'iphoneos', *arguments], text=True).strip()

sdk = xcrun('--show-sdk-path'); swiftc = xcrun('--find', 'swiftc')
accessors = sorted((IOS / '.build').rglob('resource_bundle_accessor.swift'))
accessor = next((p for p in accessors if 'FortiCore.build' in p.parts), None)
if accessor is None:
    raise SystemExit('FortiCore resource accessor missing: run swift test before iOS type-checking')
base = [swiftc, '-swift-version', '5', '-sdk', sdk, '-target', 'arm64-apple-ios16.0',
        '-parse-as-library', '-module-cache-path', str(modules / 'cache')]

def check(label, arguments):
    file = logs / ('ios-typecheck-' + label + '.log')
    print('[iOS typecheck]', label, flush=True)
    with file.open('w', encoding='utf8') as output:
        result = subprocess.run([*base, *arguments], stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        print(file.read_text(encoding='utf8', errors='replace'), flush=True)
    return result.returncode == 0

core = sorted((IOS / 'Core').glob('*.swift'))
if not check('core', ['-emit-module', '-module-name', 'FortiCore', '-emit-module-path', str(modules / 'FortiCore.swiftmodule'),
                      *map(str, core), str(accessor)]):
    raise SystemExit('iOS FortiCore type-check failed')
shared = sorted((IOS / 'Shared').glob('*.swift'))
app = check('app', ['-import-objc-header',str(IOS / 'Native/HillstoneAppBridge.h'),'-typecheck', '-module-name', 'FortiOneTap', '-I', str(modules),
                    *map(str, sorted((IOS / 'App').glob('*.swift'))), *map(str, shared)])
extension = check('tunnel', ['-typecheck', '-module-name', 'FortiTunnel', '-I', str(modules),
                            '-application-extension', '-import-objc-header', str(IOS / 'Native/FortiBridge.h'),
                            *map(str, sorted((IOS / 'Tunnel').glob('*.swift'))), *map(str, shared)])
if not app or not extension:
    raise SystemExit('iOS Swift type-check failed; app and tunnel diagnostics are both saved')
print('PASS: FortiCore, main app and VPN extension type-check against the device iOS SDK')