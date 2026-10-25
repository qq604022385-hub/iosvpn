#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
ios="$PWD"
native_stage="checking iOS toolchain"
diagnostic_log=""
report_native_failure() {
  local status=$?
  trap - ERR
  printf '::error::Native build failed during %s (exit %s).\n' "$native_stage" "$status" >&2
  if [[ -n "$diagnostic_log" && -f "$diagnostic_log" ]]; then
    printf '::group::Last 160 lines of %s\n' "$diagnostic_log"
    tail -n 160 "$diagnostic_log" || true
    printf '::endgroup::\n'
  fi
  if [[ "$native_stage" == "strongSwan" && -f "$ios/build/strongswan-ios/config.log" ]]; then
    printf '::group::Last 100 lines of strongSwan config.log\n'
    tail -n 100 "$ios/build/strongswan-ios/config.log" || true
    printf '::endgroup::\n'
  fi
  exit "$status"
}
# Emit diagnostics in the parent after the redirected subshell closes its log.
trap report_native_failure ERR
sdk="${1:-iphoneos}"
if [[ "$sdk" != iphoneos ]]; then echo "Use iphoneos for this device IPA target" >&2; exit 1; fi
mkdir -p build/native/iphoneos build/logs
python3 scripts/fetch_openssl.py
openssl_src="$ios/build/openssl-src/openssl-3.6.5"
sdk_path="$(xcrun --sdk iphoneos --show-sdk-path)"
cc="$(xcrun --sdk iphoneos --find clang)"
ar="$(xcrun --sdk iphoneos --find ar)"
ranlib="$(xcrun --sdk iphoneos --find ranlib)"
nm="$(xcrun --sdk iphoneos --find nm)"
flags=(-std=gnu11 -arch arm64 -isysroot "$sdk_path" -miphoneos-version-min=16.0 -O2 -fapplication-extension)
native_stage="OpenSSL"
diagnostic_log="$ios/build/logs/openssl.log"
# OpenSSL statically includes the default provider; no dylib, engine, or modules are loaded.
(
  cd "$openssl_src"
  unset CC CFLAGS CPPFLAGS LDFLAGS
  ./Configure ios64-xcrun no-shared no-tests no-module no-engine no-async \
    -miphoneos-version-min=16.0 -fapplication-extension --prefix="$ios/build/openssl" --libdir=lib
  make -j"$(sysctl -n hw.ncpu)" build_libs
  make install_dev
) > build/logs/openssl.log 2>&1
native_stage="Hillstone iOS C compilation"
diagnostic_log="$ios/build/logs/scvpn-ios.log"
# Compile independent C first so platform/header errors surface before the
# expensive strongSwan build. Reuse this device object during archive creation.
"$cc" "${flags[@]}" -I"$ios/Native" -I"$ios/build/openssl/include" \
  -c "$ios/Native/scvpn.c" -o "$ios/build/native/iphoneos/scvpn.o" \
  > build/logs/scvpn-ios.log 2>&1
native_stage="preparing strongSwan source"
diagnostic_log=""
python3 scripts/prepare_source.py "$ios/build/strongswan-ios"
source="$ios/build/strongswan-ios"
native_stage="strongSwan"
diagnostic_log="$ios/build/logs/strongswan.log"
(
  cd "$source"
  echo "[strongSwan] Generating configure and Makefiles"
  bash ./autogen.sh
  export CC="$cc" AR="$ar" RANLIB="$ranlib" NM="$nm"
  # gperf 3.0.3 emits K&R C, which C23 rejects. Keep the legacy engine on GNU C11.
  export CFLAGS="-std=gnu11 -arch arm64 -isysroot $sdk_path -miphoneos-version-min=16.0 -O2 -fapplication-extension -Wno-incompatible-function-pointer-types"
  export CPPFLAGS="-I$ios/build/openssl/include"
  export LDFLAGS="-arch arm64 -isysroot $sdk_path -miphoneos-version-min=16.0 -L$ios/build/openssl/lib"
  # The versionless host alias differs from config.guess and forces cross-compilation.
  echo "[strongSwan] Checking iOS compiler and dependencies"
  ./configure --build="$(./config.guess)" --host=aarch64-apple-darwin \
    --disable-defaults --enable-monolithic --enable-static --disable-shared \
    --enable-charon --enable-ikev1 --enable-openssl --enable-nonce --enable-hmac \
    --enable-kernel-libipsec --enable-socket-default --enable-vici --enable-xauth-generic \
    --with-printf-hooks=builtin --with-strongswan-conf= --with-piddir=/tmp \
    --with-capabilities=no --disable-warnings
  echo "[strongSwan] Building libstrongswan"
  make -j"$(sysctl -n hw.ncpu)" -C src/libstrongswan
  echo "[strongSwan] Building libipsec"
  make -j"$(sysctl -n hw.ncpu)" -C src/libipsec
  echo "[strongSwan] Building libcharon"
  make -j"$(sysctl -n hw.ncpu)" -C src/libcharon
) > build/logs/strongswan.log 2>&1
native_stage="iOS bridge compilation and static linking"
diagnostic_log="$ios/build/logs/bridge-link.log"
(
  # Match the original VICI Makefile's definitions. On iOS its default URI
  # references IPSEC_PIDDIR; Windows hides that requirement behind #ifdef WIN32.
  includes=(-I"$source" -I"$source/src/libstrongswan" -I"$source/src/libcharon"
    -I"$source/src/libipsec" -I"$source/src/libcharon/plugins/vici"
    -I"$source/src/libstrongswan/plugins/pubkey" -I"$source/src/libcharon/plugins/counters"
    -I"$ios/Native" -I"$ios/build/openssl/include" -include "$source/config.h"
    '-DIPSEC_PIDDIR="/tmp"' '-DSWANCTLDIR="/tmp/swanctl"')
  objects=("$ios/build/native/iphoneos/scvpn.o")
  failed=0
  for file in "$ios/Native/FortiBridge.c" "$ios/Native/kernel_net_ios.c" "$source/src/libcharon/plugins/vici/libvici.c"; do
    object="$ios/build/native/iphoneos/$(basename "${file%.c}").o"
    echo "[bridge] Compiling $(basename "$file")"
    if "$cc" "${flags[@]}" "${includes[@]}" -c "$file" -o "$object"; then
      objects+=("$object")
    else
      failed=1
    fi
  done
  if [[ "$failed" != 0 ]]; then
    echo "::error::Bridge compilation failed; all source diagnostics are listed above."
    exit 1
  fi
  # Common VICI implementations already exist in libcharon's VICI plugin;
  # only libvici.c is added to prevent duplicate definitions.
  echo "[bridge] Combining device static libraries"
  xcrun libtool -static -o build/native/iphoneos/libFortiEngine.a \
    "${objects[@]}" "$source/src/libcharon/.libs/libcharon.a" \
    "$source/src/libstrongswan/.libs/libstrongswan.a" "$source/src/libipsec/.libs/libipsec.a" \
    "$ios/build/openssl/lib/libssl.a" "$ios/build/openssl/lib/libcrypto.a"
  xcrun lipo -info build/native/iphoneos/libFortiEngine.a
  # Resolve every native symbol before the Swift/Xcode stage. This test dylib
  # is a build-only artifact and is never embedded in the app or IPA.
  echo "[bridge] Checking complete iOS native symbol resolution"
  "$cc" "${flags[@]}" -dynamiclib -Wl,-force_load,"$ios/build/native/iphoneos/libFortiEngine.a" \
    -framework Security -lm -o "$ios/build/native/iphoneos/link-check.dylib"
) > build/logs/bridge-link.log 2>&1
