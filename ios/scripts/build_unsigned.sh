#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts build/logs
if [[ "${FORTI_BUILD_LOG_ACTIVE:-0}" != 1 ]]; then
  export FORTI_BUILD_LOG_ACTIVE=1
  set +e
  bash "$PWD/scripts/build_unsigned.sh" "$@" 2>&1 | tee build/logs/full-build.log
  statuses=("${PIPESTATUS[@]}")
  result="${statuses[0]}"
  if [[ "$result" == 0 && "${statuses[1]}" != 0 ]]; then result="${statuses[1]}"; fi
  exit "$result"
fi
python3 scripts/check_shell_scripts.py
python3 scripts/verify_source.py
python3 scripts/test_host.py 2>&1 | tee build/logs/host-tests.log
python3 scripts/test_native.py 2>&1 | tee build/logs/native-host-tests.log
python3 scripts/test_processor.py 2>&1 | tee build/logs/processor-host-tests.log
swift test --package-path . 2>&1 | tee build/logs/core-tests.log
python3 scripts/typecheck_ios.py
bash scripts/build_native.sh
xcodegen generate --spec project.yml 2>&1 | tee build/logs/xcodegen.log
xcodebuild -project FortiOneTap.xcodeproj -scheme FortiOneTap -configuration Release \
  -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath build/xcode \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build 2>&1 | tee build/logs/xcodebuild.log
python3 scripts/package_ipa.py build/xcode/Build/Products/Release-iphoneos/FortiOneTap.app artifacts/FortiOneTap-unsigned.ipa
python3 scripts/verify_ipa.py artifacts/FortiOneTap-unsigned.ipa
