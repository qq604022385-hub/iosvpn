#!/usr/bin/env python3
"""Tests for packaging/validation only; synthetic fixtures are not runnable IPA files."""
import hashlib, plistlib, shutil, struct, tempfile, unittest, zipfile, subprocess, os, sys
import io
from unittest import mock
from pathlib import Path
from package_ipa import package
from verify_ipa import verify, macho_device
from prepare_source import copy_tree, patch, normalize_tree, IOS
from check_shell_scripts import check_shell_scripts
import test_native

class HostTests(unittest.TestCase):
    def setUp(self):
        (IOS / "build").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="host-tests-", dir=IOS / "build")
        self.directory = Path(self.temp.name).resolve()
        assert self.directory.is_relative_to((IOS / "build").resolve())
    def tearDown(self): self.temp.cleanup()
    def binary(self, platform=2, cpu=0x100000c):
        return struct.pack("<8I", 0xfeedfacf, cpu, 0, 2, 1, 24, 0, 0) + struct.pack("<6I", 0x32, 24, platform, 0x100000, 0x100000, 0)
    def app(self):
        app = self.directory / "FortiOneTap.app"; extension = app / "PlugIns/FortiTunnel.appex"
        extension.mkdir(parents=True)
        (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "test.forti", "CFBundleExecutable": "FortiOneTap"}))
        (extension / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "test.forti.Tunnel", "CFBundleExecutable": "FortiTunnel",
            "NSExtension": {"NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel", "NSExtensionPrincipalClass": "FortiTunnel.PacketTunnelProvider"}}))
        for parent, name in [(app, "FortiOneTap"), (extension, "FortiTunnel")]:
            (parent / name).write_bytes(self.binary()); (parent / name).chmod(0o755)
        resources = extension / "FortiCore_FortiCore.bundle"; resources.mkdir()
        shutil.copy2(IOS / "Core/Resources/cn-ipv4.txt", resources)
        return app
    def test_device_architecture_validation(self):
        macho_device(self.binary())
        for invalid in [self.binary(platform=7), self.binary(cpu=0x1000007), b"not executable"]:
            with self.assertRaises(ValueError): macho_device(invalid)
    def test_payload_extension_and_checksums(self):
        app = self.app(); output = self.directory / "fixture.ipa"
        checksum = package(app, output)
        self.assertEqual(checksum, hashlib.sha256(output.read_bytes()).hexdigest())
        self.assertEqual(verify(output)["extension"], "test.forti.Tunnel")
        with zipfile.ZipFile(output) as archive:
            self.assertTrue(all(n.startswith("Payload/FortiOneTap.app/") for n in archive.namelist()))
    def test_missing_extension_is_rejected(self):
        app = self.app(); extension = app / "PlugIns/FortiTunnel.appex"
        (extension / "Info.plist").unlink()
        output = self.directory / "fixture.ipa"; package(app, output)
        with self.assertRaisesRegex(ValueError, "embedded VPN"): verify(output)
    def test_route_corruption_is_rejected(self):
        app = self.app(); (app / "PlugIns/FortiTunnel.appex/FortiCore_FortiCore.bundle/cn-ipv4.txt").write_text("0.0.0.0/0\n")
        output = self.directory / "fixture.ipa"; package(app, output)
        with self.assertRaisesRegex(ValueError, "snapshot mismatch"): verify(output)
    def test_signing_material_is_rejected(self):
        app = self.app(); (app / "embedded.mobileprovision").write_text("test")
        output = self.directory / "fixture.ipa"; package(app, output)
        with self.assertRaisesRegex(ValueError, "signing material"): verify(output)
    def test_sandboxed_source_and_xauth_patch(self):
        source = copy_tree(self.directory / "source"); patch(source)
        self.assertNotIn(b"\r", (source / "scripts/git-version").read_bytes())
        self.assertTrue((source / "src/libstrongswan/plugins/openssl/openssl_plugin.c").is_file())
        self.assertIn("fot_deliver", (source / "src/libstrongswan/networking/tun_device.c").read_text(encoding="utf8"))
        self.assertIn('"pin"', (source / "src/libcharon/plugins/vici/vici_cred.c").read_text(encoding="utf8"))
        self.assertIn("forti_xauth_append", (source / "src/libcharon/plugins/xauth_generic/xauth_generic.c").read_text(encoding="utf8"))
        self.assertIn("chunk_clear(&this->encoding)", (source / "src/libcharon/plugins/vici/vici_message.c").read_text(encoding="utf8"))
        self.assertNotIn("CAP_NET_ADMIN", (source / "src/libcharon/plugins/kernel_libipsec/kernel_libipsec_plugin.c").read_text(encoding="utf8"))
    def test_extensionless_script_normalization(self):
        script = self.directory / "git-version"
        script.write_bytes(b"#!/bin/sh\r\necho test-version\r\n")
        script.chmod(0o755)
        before_mode = script.stat().st_mode
        normalize_tree(self.directory)
        self.assertEqual(script.read_bytes(), b"#!/bin/sh\necho test-version\n")
        self.assertEqual(script.stat().st_mode, before_mode)
    def test_normalizer_preserves_binary_and_non_source_files(self):
        binary = self.directory / "data.c"
        raw_binary = b"\0\xff\r\n\x01"
        binary.write_bytes(raw_binary)
        ordinary = self.directory / "plain-file"
        ordinary.write_bytes(b"ordinary data\r\n")
        normalize_tree(self.directory)
        self.assertEqual(binary.read_bytes(), raw_binary)
        self.assertEqual(ordinary.read_bytes(), b"ordinary data\r\n")
    def test_shell_preflight_accepts_lf_without_modifying_script(self):
        script = self.directory / "build_native.sh"
        raw = b"#!/usr/bin/env bash\nset -euo pipefail\n"
        script.write_bytes(raw)
        self.assertEqual(check_shell_scripts(self.directory), 1)
        self.assertEqual(script.read_bytes(), raw)
    def test_shell_preflight_rejects_crlf_with_path_and_line(self):
        scripts = self.directory / "scripts"; scripts.mkdir()
        script = scripts / "build_native.sh"
        raw = b"#!/usr/bin/env bash\nset -euo pipefail\r\n"
        script.write_bytes(raw)
        result = subprocess.run([sys.executable, str(IOS / "scripts/check_shell_scripts.py"),
                                 str(self.directory)], capture_output=True, text=True,
                                encoding="utf8", env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("build_native.sh:2: CR/CRLF detected", result.stderr)
        self.assertEqual(script.read_bytes(), raw)
    def test_shell_preflight_rejects_bom(self):
        (self.directory / "build_native.sh").write_bytes(b"\xef\xbb\xbf#!/bin/bash\n")
        with self.assertRaisesRegex(ValueError, "UTF-8 BOM"):
            check_shell_scripts(self.directory)
    def test_shell_preflight_rejects_missing_scripts(self):
        with self.assertRaisesRegex(ValueError, "No shell scripts"):
            check_shell_scripts(self.directory)
    def test_macos_native_command_uses_host_sdk_despite_ios_environment(self):
        # Test command construction only. These empty fixture headers are never
        # compiled and do not stand in for an actual Apple SDK build.
        sdk = self.directory / "MacOSX.sdk"
        (sdk / "usr/include").mkdir(parents=True)
        (sdk / "usr/include/stdlib.h").write_bytes(b"")
        prefix = self.directory / "openssl"
        (prefix / "include/openssl").mkdir(parents=True)
        (prefix / "include/openssl/ssl.h").write_bytes(b"")
        argv = ["test_native.py", "--cc", sys.executable, "--openssl-prefix", str(prefix)]
        discovery_sdkroots = []
        def discover_sdk(*args, **kwargs):
            discovery_sdkroots.append(kwargs["env"].get("SDKROOT"))
            return str(sdk)
        with mock.patch.object(test_native.sys, "platform", "darwin"), \
             mock.patch.object(test_native.sys, "argv", argv), \
             mock.patch.dict(os.environ, {"SDKROOT": "/bad/iPhoneOS.sdk", "IPHONEOS_DEPLOYMENT_TARGET": "16.0"}), \
             mock.patch.object(test_native.subprocess, "check_output", side_effect=discover_sdk) as discover, \
             mock.patch.object(test_native, "run") as execute, \
             mock.patch.object(sys, "stdout", io.StringIO()):
            test_native.main()
        discovery_args = discover.call_args
        self.assertEqual(discovery_args.args[0], ["xcrun", "--sdk", "macosx", "--show-sdk-path"])
        self.assertEqual(discovery_sdkroots, [None])
        compile_call = execute.call_args_list[1]
        command = list(map(str, compile_call.args[0]))
        self.assertEqual(command[command.index("-isysroot") + 1], str(sdk))
        self.assertEqual(compile_call.kwargs["env"]["SDKROOT"], str(sdk))
        self.assertIsNone(compile_call.kwargs["env"].get("IPHONEOS_DEPLOYMENT_TARGET"))
    def test_macos_native_command_rejects_sdk_without_standard_headers(self):
        argv = ["test_native.py", "--cc", sys.executable, "--openssl-prefix", str(self.directory)]
        with mock.patch.object(test_native.sys, "platform", "darwin"), \
             mock.patch.object(test_native.sys, "argv", argv), \
             mock.patch.object(test_native.subprocess, "check_output", return_value=str(self.directory)), \
             mock.patch.object(test_native, "run") as execute, \
             mock.patch.object(sys, "stderr", io.StringIO()) as diagnostic:
            with self.assertRaises(SystemExit) as failure:
                test_native.main()
        self.assertEqual(failure.exception.code, 2)
        self.assertIn("Resolved macOS SDK has no stdlib.h", diagnostic.getvalue())
        execute.assert_not_called()
    def test_full_build_log_keeps_stderr_and_failure_status(self):
        bash = shutil.which("bash")
        if not bash and os.name == "nt":
            candidate = Path("C:/Program Files/Git/bin/bash.exe")
            if candidate.is_file(): bash = str(candidate)
        if not bash:
            self.skipTest("Bash not resolved in this test environment")
        root = self.directory / "logger-proof"
        scripts = root / "scripts"; scripts.mkdir(parents=True)
        original = (IOS / "scripts/build_unsigned.sh").read_text(encoding="utf8")
        prefix = original.split("python3 scripts/check_shell_scripts.py", 1)[0]
        script = scripts / "build_unsigned.sh"
        script.write_bytes((prefix + 'printf "TEST ONLY: stdout\\n"\nprintf "TEST ONLY: bridge failure\\n" >&2\nexit 7\n').encode("utf8"))
        env = dict(os.environ); env.pop("FORTI_BUILD_LOG_ACTIVE", None)
        result = subprocess.run([bash, str(script)], env=env, capture_output=True, text=True, encoding="utf8")
        self.assertEqual(result.returncode, 7, result.stderr)
        log = (root / "build/logs/full-build.log").read_text(encoding="utf8")
        self.assertIn("TEST ONLY: stdout", log)
        self.assertIn("TEST ONLY: bridge failure", log)
    def test_source_destination_outside_build_is_rejected(self):
        with self.assertRaises(ValueError): copy_tree(IOS / "App")
if __name__ == "__main__": unittest.main(verbosity=2)
