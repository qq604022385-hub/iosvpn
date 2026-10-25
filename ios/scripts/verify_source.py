#!/usr/bin/env python3
"""Host-side integration checks. These are not a replacement for an Xcode build."""
from pathlib import Path
import hashlib, ipaddress, json, re
IOS = Path(__file__).resolve().parents[1]
ROOT = IOS.parent
lock = json.loads((IOS / "dependencies.lock.json").read_text(encoding="utf8"))
routes_file = IOS / "Core/Resources/cn-ipv4.txt"
assert hashlib.sha256(routes_file.read_bytes()).hexdigest() == lock["cn_ipv4"]["sha256"]
ranges = [ipaddress.IPv4Network(s.strip(), strict=True) for s in routes_file.read_text(encoding="utf8").splitlines() if s.strip() and not s.startswith("#")]
assert len(ranges) == lock["cn_ipv4"]["count"]
assert all(r.prefixlen >= 4 for r in ranges)
assert all(ipaddress.IPv4Address("1.1.1.1") not in r for r in ranges)
assert (IOS / "Core/Resources/APNIC-NOTICE.txt").is_file()
bridge = (IOS / "Native/FortiBridge.c").read_text(encoding="utf8")
if (ROOT / "windows/Core.cs").exists():
    windows = (ROOT / "windows/Core.cs").read_text(encoding="utf8")
    for value in ["aes128-sha1-modp1536", "aes256-sha256-modp1536", "aes256-sha1-modp1536", "84600s", "1800s", "43200s", "42120s"]:
        assert value in bridge and value in windows, "Protocol mismatch: " + value
assert 'kv(r, "timeout", "30000")' in bridge, "VICI timeout is milliseconds"
assert '"unload-shared"' in bridge and '"token"' in bridge
assert 'child->get_state(child) != CHILD_INSTALLED' in bridge
assert 'ts->get_from_port(ts) == 0 && ts->get_to_port(ts) == 65535' in bridge
assert 'vici_add_key_value' in bridge and 'vici_submit' in bridge
xauth = (IOS / "Native/xauth_generic_ios.c").read_text(encoding="utf8")
assert "SHARED_PIN" in xauth and "forti_xauth_append" in xauth and "password_round" in xauth
assert "chunk_clear(&combined)" in xauth
app = (IOS / "App/VPNController.swift").read_text(encoding="utf8")
assert 'startTunnel(options:' in app and '"attemptID"' in app
assert 'isOnDemandEnabled = false' in app and 'disconnectOnSleep = false' in app
assert '"profileVersion": 2' in app and '"provider": hillstone ? "hillstone" : "forti"' in app
assert 'm.isOnDemandEnabled = true' in app and 'NEOnDemandRuleConnect()' in app
disconnect = app.split('    func disconnect()', 1)[1].split('    private func refresh()', 1)[0]
assert disconnect.index('isOnDemandEnabled = false') < disconnect.index('saveToPreferences()') < disconnect.index('stopVPNTunnel()')
provider = (IOS / "Tunnel/PacketTunnelProvider.swift").read_text(encoding="utf8")
assert 'nativeReady, networkReady' in provider
assert 'NEIPv6Route.default()' in provider
assert 'setTunnelNetworkSettings(nil)' in provider
assert 'packetGate.ingest' in provider
assert 'lastConsumedAttempt' in provider
assert 'saved?["provider"]' in provider and 'recoverHillstone' in provider
assert 'reasserting = true' in provider and 'reasserting = false' in provider
recovery = provider.split('    private func recoverHillstone', 1)[1].split('    private func disableOnDemandAfterFailure', 1)[0]
assert 'generation = UUID()' in recovery and 'engine.afterStopped(on: stateQueue)' in recovery
assert 'setTunnelNetworkSettings(nil)' not in recovery, 'Retain system VPN routes during transient recovery'
assert 'retryWork?.cancel()' in provider.split('override func stopTunnel', 1)[1]
assert 'packetReadInFlight' in provider and 'self.sessionID == sessionID' in provider
assert 'requestNetworkValidation()' in provider.split('override func wake()', 1)[1]
metadata = app.split('config.providerConfiguration = ', 1)[1].split('\n', 1)[0]
assert set(re.findall(r'[\[,]\s*"(\w+)"\s*:', metadata)) == {'profileVersion', 'provider', 'keepConnected'}, 'Persist only non-secret provider metadata'
project = (IOS / "project.yml").read_text(encoding="utf8")
assert project.count('packet-tunnel-provider') == 2
assert project.count('keychain-access-groups: ["$(AppIdentifierPrefix)$(BUNDLE_ID)"]') == 2
assert 'target: FortiTunnel' in project and 'embed: true' in project
assert '-force_load' in project and 'libFortiEngine.a' in project
for file in IOS.rglob("*"):
    if file.is_file() and file.suffix in {".swift", ".py", ".sh", ".c", ".h", ".yml", ".json"} and not any(s in file.parts for s in ["build", ".build", "artifacts", ".swiftpm"]):
        assert not file.read_bytes().startswith(b"\xef\xbb\xbf"), "Unexpected UTF-8 BOM: " + str(file)
print(f"PASS: protocol parity, token lifecycle, tunnel integration, entitlement declarations and {len(ranges)} route resources")
# Independent Hillstone engine and first-use certificate onboarding integration.
certificate=(IOS / "App/HillstoneCertificate.swift").read_text(encoding="utf8")
assert "hs_probe_certificate" in certificate and "SecPolicyCreateSSL(true" in certificate
assert "SecTrustEvaluateWithError" in certificate and "SHA256.hash" in certificate
assert "certificateDecision" in app and "profile.certificatePin.lowercased()==certificate.pin" in app
assert "HillstoneKeychain.save" in app and '"provider"' in app
assert "HillstoneTunnel()" in provider and "certificatePin.isEmpty" in provider
assert "Native/HillstoneAppBridge.h" in project
engine=(IOS / "Native/scvpn.c").read_text(encoding="utf8")
assert "hs_probe_certificate" in engine and "hs_connect" in engine
assert "socklen_t local_size" in engine
print("PASS: Hillstone source integration, certificate trust flow and portable native ABI")

# Log persistence and Hillstone ingress must stay bounded outside the data hot path.
store=(IOS / "Shared/DiagnosticsStore.swift").read_text(encoding="utf8")
worker=(IOS / "Tunnel/HillstoneTunnel.swift").read_text(encoding="utf8")
assert "BoundedDiagnostics" in provider and "logLines.append" not in provider
assert "receiveHillstone" in provider and "stateQueue.sync" in provider
assert "PacketBatch()" in worker and "packets(batch.takePackets())" in worker
assert "writer.asyncAfter" in store and "pending=bounded" in store
assert "DiagnosticsStore.flush()" in provider
assert "UIApplication.shared.applicationState == .active" in app
assert "UserDefaults.standard.set(text" not in app
print("PASS: bounded log/batch integration, coalesced persistence and foreground log polling")

assert 'case "phase"' in provider and 'notify("phase", name)' in bridge
assert 'reason.rawValue' in provider and 'override func sleep' in provider and 'override func wake' in provider
assert 'fortiPathRecovery.observe(valid:' in provider
assert 'networkFailures >= 3' not in provider, 'Transient path loss must not destroy the authenticated Forti session'
assert 'self.fortiProbeID==probeID' in provider, 'Ignore probe timeouts from an earlier network path'
assert 'resume_until' in engine and 'last_receive_tick' in engine
assert 'direct_avg_ms' in (IOS / 'Native/dns_probe.h').read_text(encoding='utf8')
print('PASS: sleep persistence, stop reasons, Forti phases and DNS latency diagnostics')

assert '"charon.threads", 16' in bridge and '"charon.threads", 8' not in bridge
assert 'vici_begin("version")' in bridge and 'hs_select_public_dns(pointer)' in worker
assert 'syn_avg_ms' in (IOS/'Native/dns_probe.h').read_text(encoding='utf8')
assert 'test_processor.py' in (IOS/'scripts/build_unsigned.sh').read_text(encoding='utf8')
print('PASS: Forti worker capacity/self-check and in-VPN DNS selection/TCP timing')

# Both targets fetch fresh OTPs without saving them in VPN metadata.
token_client = (IOS / 'Shared/TokenClient.swift').read_text(encoding='utf8')
token_parser = (IOS / 'Core/TokenResponse.swift').read_text(encoding='utf8')
view = (IOS / 'App/FortiOneTapApp.swift').read_text(encoding='utf8')
assert 'http://47.103.139.56:9000/api/key' in token_client
assert 'URLSessionConfiguration.ephemeral' in token_client and 'completionHandler(nil)' in token_client
assert 'config.urlCache = nil' in token_client and 'config.httpCookieStorage = nil' in token_client
assert 'http.statusCode == 200' in token_client and 'data.count < 64' in token_client
assert 'timeoutIntervalForResource = 10' in token_client and 'session.invalidateAndCancel()' in token_client
assert 'SiteSettings.validateToken(token)' in token_parser and 'data.count <= 64' in token_parser
assert app.index('try await m.saveToPreferences(); try await m.loadFromPreferences()') < app.index('once = try await TokenClient.fetch()') < app.index('try session.startTunnel(options:')
assert 'needsManualToken = true' in app and '$vpn.needsManualToken' in view
assert 'NSExceptionAllowsInsecureHTTPLoads: true' in project and '"47.103.139.56":' in project
assert 'NSAllowsArbitraryLoads' not in project
assert 'TokenClient.fetch()' in provider and 'self.tokenTask?.cancel()' in provider
assert 'recoverForti' in provider and 'fot_stop()' in provider
assert 'm.onDemandRules = [rule]' in app
assert app.index('try session.startTunnel(options:') < app.index('m.isOnDemandEnabled = true')
print('PASS: fresh Forti OTP request, strict parsing, manual fallback and scoped HTTP allowance')
