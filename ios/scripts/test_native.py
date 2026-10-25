#!/usr/bin/env python3
"""Compile and run actual SCVPN C regression tests on the build host, not iOS."""
from pathlib import Path
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

IOS = Path(__file__).resolve().parents[1]


def run(arguments, env=None):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True,
                            encoding="utf8", errors="replace", env=env, timeout=120, cwd=IOS)
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr, flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", help="Explicit host C compiler")
    parser.add_argument("--openssl-prefix", type=Path, help="Host OpenSSL include/lib prefix")
    args = parser.parse_args()
    prefix = args.openssl_prefix
    if prefix is not None:
        prefix = prefix.resolve()
    compiler = args.cc
    env = dict(os.environ)
    sdk_flags = []
    if sys.platform == "darwin":
        # This executable runs on the build host. An iPhone SDK inherited from
        # another build step must never select its headers or deployment target.
        for key in ["SDKROOT", "IPHONEOS_DEPLOYMENT_TARGET", "MACOSX_DEPLOYMENT_TARGET"]:
            env.pop(key, None)
        sdk = Path(subprocess.check_output(
            ["xcrun", "--sdk", "macosx", "--show-sdk-path"],
            text=True, env=env, timeout=30).strip())
        if not (sdk / "usr/include/stdlib.h").is_file():
            parser.error(f"Resolved macOS SDK has no stdlib.h: {sdk}")
        # --find resolves a compiler path but does not apply xcrun's SDK
        # environment to later invocations of that path. Pass it explicitly.
        sdk_flags = ["-isysroot", str(sdk)]
        env["SDKROOT"] = str(sdk)
        compiler = compiler or subprocess.check_output(
            ["xcrun", "--sdk", "macosx", "--find", "clang"],
            text=True, env=env, timeout=30).strip()
        if prefix is None:
            prefix = Path(subprocess.check_output(
                ["brew", "--prefix", "openssl@3"], text=True, env=env, timeout=30).strip())
        print(f"[native host tests] macOS SDK: {sdk}", flush=True)
    elif os.name == "nt":
        prefix = prefix or IOS.parent / "windows/build-deps/toolchain/mingw64"
        compiler = compiler or str(prefix / "bin/gcc.exe")
    else:
        compiler = compiler or shutil.which("cc")
    if not compiler or not prefix or not (prefix / "include/openssl/ssl.h").is_file():
        parser.error("Provide a resolved host compiler (--cc) and OpenSSL prefix (--openssl-prefix)")
    compiler_directory = Path(shutil.which(compiler) or compiler).resolve().parent
    env["PATH"] = str(compiler_directory) + os.pathsep + str(prefix / "bin") + os.pathsep + env.get("PATH", "")
    run([compiler, "--version"], env=env)
    (IOS / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="native-tests-", dir=IOS / "build") as temp:
        executable = Path(temp) / ("scvpn-tests.exe" if os.name == "nt" else "scvpn-tests")
        # GNU binutils on Windows cannot reliably consume non-ASCII absolute
        # output paths. Run from ios and use relative paths for compile inputs.
        try:
            include_prefix = Path(os.path.relpath(prefix, IOS))
        except ValueError:
            include_prefix = prefix
        command = [compiler, *sdk_flags, "-std=gnu11", "-O2", "-Wall", "-Wextra",
                   "-Werror=implicit-function-declaration", "-Werror=incompatible-pointer-types",
                   "-Werror=return-type", "-I" + str(include_prefix / "include"),
                   "NativeTests/scvpn_test.c", "-L" + str(include_prefix / "lib"),
                   "-lssl", "-lcrypto", "-o", executable.relative_to(IOS)]
        if os.name == "nt":
            command.append("-B" + str(include_prefix / "lib") + os.sep)
            for directory in sorted((prefix / "lib/gcc").glob("*/*")):
                if directory.is_dir():
                    command.append("-B" + os.path.relpath(directory, IOS) + os.sep)
            command.extend(["-lws2_32", "-lcrypt32", "-lbcrypt"])
        run(command, env=env)
        run([executable], env=env)
        # The same real-UDP initial-path failure cases also run in macOS CI.
        wifi_command = list(command)
        wifi_command[wifi_command.index("NativeTests/scvpn_test.c")] = "NativeTests/wifi_udp_test.c"
        run(wifi_command, env=env)
        run([executable], env=env)
    print("PASS: host C compilation, libc namespace compatibility and native network checks")


if __name__ == "__main__":
    main()
