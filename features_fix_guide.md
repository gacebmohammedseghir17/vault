# ERDPS Features Fix Guide

## Goal
Make each non-functional or partially functional feature work, ordered by priority (impact × ease). Includes exact commands, prerequisites, and file references.

## Critical Priority
- Fix IPC Port Mismatches [COMPLETED]
  - Actual State: Agent listens on `127.0.0.1:8888` (from `config.toml`). Some test binaries previously attempted to connect to `7777`.
  - What We Fixed:
    - Updated hardcoded ports in test binaries to use `8888` and to load address via `AgentConfig`.
    - Standardized clients to respect `service.ipc_bind` from `config.toml`.
  - Files Updated: `src/bin/simple_ipc_test.rs`, `src/bin/test_alert_delivery.rs`, `src/bin/comprehensive_alert_test.rs`
  - Quick Commands (verified):
    - `cargo run --bin erdps-agent` (agent starts; IPC on `127.0.0.1:8888`)
    - `cargo run --bin ipc_client -- --server 127.0.0.1:8888` → getStatus success, signature verifies
    - `cargo run --bin simple_ipc_test` → getStatus success, signature verifies
    - `cargo run --bin test_alert_delivery` → status success; listens for alerts (no events by default)
  - Config Note: To change the IPC port, edit `agent/config.toml` → `service.ipc_bind = "127.0.0.1:<port>"`.
  - Original Guide Correction: The prior guidance referenced `7777/7778`. The working config uses `8888`; clients are now aligned to `8888`.

- Standardize IPC Signatures [IN PROGRESS]
  - Goal: Ensure all clients use identical signing, canonicalization, and framing.
  - Completed:
    - Rust test binaries (`simple_ipc_test`, `test_alert_delivery`) now reuse shared `ipc::sign`, canonical JSON, and length-prefixed framing.
    - `ipc_client` already conforms; response signatures verify.
  - Next Actions:
    - Audit any non-Rust clients (e.g., Node/Electron) for `HMAC-SHA256`, base64, canonical JSON, and length-prefixed framing.
    - Provide test vectors (request/response) and a mini "signature conformance" doc.
    - Add unit tests around `ipc::sign` with cross-language fixtures.
  - Artifacts/Config: Use unified key from `agent/config.toml` → `ipc_key` (base64, 32 bytes).

- YARA Rules Consistency
  - Problem: Previously suspected rule compile failures.
  - Current Status: Baseline `rules` directory compiles successfully (recursive load) using `yara_x`.
  - Verification:
    - `python validate_yara_rules.py rules` → 2 files validated; 7 unique rules reported.
    - `cargo run --bin test_yara_compile` → Successfully compiled 23,215 rules from nested directories; engine reports loaded=true.
  - Next Actions:
    - Keep `minimal_safe.yar` as guaranteed-safe baseline; use `test_yara_compile` to spot regressions after rule updates.
    - If adding external rule packs, run the validator, then the compile test to catch syntax/unsupported constructs.
  - Files: `rules/`, `src/detection/yara_engine.rs`, `src/bin/test_yara_compile.rs`, `docs/yara_configuration.md`

## High Priority
- Enable Disassembly (Capstone)
  - Purpose: Advanced x86/x64 disassembly for pattern detection.
  - Prereqs (Windows): MSVC Build Tools, C Toolchain.
  - Status: COMPLETED — Capstone feature compiles and tests pass.
  - Enable: `cargo run --release --features advanced-disassembly`
  - Files: `src/disassembly/capstone_engine.rs`, `src/disassembly/mod.rs`, `src/lib.rs` (exports gated by feature)
  - Verification:
    - `cargo test --release --features advanced-disassembly -- disassembly --nocapture`
    - Fixed tests: adjusted NOP sled detection to avoid duplicate matches; ensured instruction pattern test aligns with tokenized matching.
  - Notes: Without feature, stub returns minimal results.

- Enhanced Network Monitoring (PCAP/TLS/X509)
  - Purpose: Deeper packet inspection and TLS metadata.
  - Prereqs (Windows): Install Npcap (admin). Verify: `./verify_npcap.ps1`
  - Enable minimal: `cargo run --release --features network-monitoring`
  - Enable full: `cargo run --release --features enhanced-pcap`
  - Files: `src/network/*`

- AI Integration (ONNX / OLLAMA)
  - Purpose: ML-based detection and enrichment.
  - Prereqs:
    - Place model: `models/ember_model.onnx` (exists)
    - ONNX Runtime: set `ORT_DYLIB_PATH` if required by environment.
    - Optional: configure `ollama` endpoint in `agent.toml`.
  - Enable: `cargo run --release --features ai-integration`
  - Files: `src/ai/*`, `models/ember_model.onnx`

## Medium Priority
- Windows Service Mode
  - Purpose: Install/run agent as Windows service.
  - Prereqs: Admin PowerShell, `windows-service` feature.
  - Enable: `cargo build --release --features windows-service`
  - Operate: If service CLI flags exist in `src/service.rs`, use them; otherwise add a thin wrapper to call `install_service()`, `start_service()`, `stop_service()`.
  - Files: `src/service.rs`

- Telemetry & Prometheus
  - Purpose: Metrics export and observability.
  - Enable metrics only: `cargo run --release --features metrics`
  - Enable telemetry: `cargo run --release --features telemetry`
  - Configure Prometheus: use `prometheus.yml`; import `grafana-dashboard.json` in Grafana.
  - Files: `src/monitoring/*`, `src/observability/*`, `prometheus.yml`, `grafana/`

- Memory Forensics
  - Purpose: PE/ELF parsing and memory scanning pathways.
  - Already enabled by default: `memory-forensics`
  - Strengthen: run the optimized analyzer or integrated analyzer code paths.
  - Files: `src/memory/*`

## Low Priority / Conceptual
- Threat Scoring (ML)
  - Status: ❌ Model/scaler missing.
  - Path to functional:
    - Provide a trained model and scaler files or implement a heuristic score fallback.
    - Wire inputs in `src/correlation/threat_scorer.rs` and expose results in IPC/alerts.
  - Files: `src/correlation/threat_scorer.rs`

- HTTP Dashboard UI
  - Status: ❌ No functional web UI.
  - Path to functional:
    - Implement Axum routes and templates using `askama_axum`.
    - Expose endpoints for status, metrics, and events.
    - Files: `src/enterprise/dashboard.rs`, `src/observability/dashboard.rs`

## Verification Steps
- Start Agent
  - `cargo run --release`
  - Expect logs: IPC server on `127.0.0.1:8888`, file monitor started.

- IPC Status & Quarantine
  - `cargo run --bin ipc_client -- --server 127.0.0.1:8888`
  - `cargo run --bin ipc_client -- --server 127.0.0.1:8888 quarantine ./test_story.txt`

- Disassembly Test (after enabling feature)
  - Create a small x86 blob; run unit tests in `src/disassembly/capstone_engine.rs` or add a CLI wrapper.

- Network Capture (after Npcap)
  - Observe logs from `src/network/*` detectors when `enhanced-pcap` enabled.

## Troubleshooting
- Build errors on Capstone/ONNX: Ensure MSVC and environment vars; retry with clean build `cargo clean && cargo build`.
- IPC issues: Align ports; confirm signatures with `debug_*` tools; check key `ipc.key`.
- YARA compile errors: Validate syntax; isolate failing rule; rely on `minimal_safe.yar` baseline.
# Enhanced Network Monitoring Fix Guide

This guide documents fixes applied to enable packet inspection and TLS metadata analysis with the `enhanced-pcap` and `network-monitoring` features.

## Environment Verification
- Verified Npcap installation via `verify_npcap.ps1` (service `npcap` running).
- Ensure Windows service `npcap` is started and device capture permissions are available.

## etherparse 0.14 API Adjustments
- Use `packet.net` instead of the deprecated `packet.ip`.
- Extract IPv4/IPv6 addresses via `Ipv4Slice::header().source_addr()/destination_addr()` and `Ipv6Slice::header().source_addr()/destination_addr()`.
- Prefer transport payloads (`TcpSlice::payload()`, `UdpSlice::payload()`, `Icmpv4Slice::payload()`, `Icmpv6Slice::payload()`).
- For network layer payloads, use `net_slice.ip_payload_ref()` and read `IpPayloadSlice.payload` field.
- For link layer payloads, use `link.payload()` to get `EtherPayloadSlice` then read `.payload` field.
- Removed ARP arm from `InternetSlice` match (not present in 0.14).
- Added ICMPv4/v6 match arms to `TransportSlice` for exhaustiveness.

## Code Changes
- File: `agent/src/network/enhanced/packet_analyzer.rs`
  - Fixed IP address extraction and payload selection order.
  - Added ICMPv4/v6 handling in transport matching and payload extraction.
  - Adjusted field vs method usage for `IpPayloadSlice` and `EtherPayloadSlice`.

- File: `agent/src/network/enhanced/pcap_analyzer.rs`
  - Derived `PartialEq` for `ThreatLevel` to satisfy tests comparing threat levels.

## Build and Test Commands
- Minimal monitoring: `cargo run --release --features network-monitoring --bin erdps-agent`
- Enhanced PCAP: `cargo run --release --features enhanced-pcap --bin erdps-agent`
- Focused TLS test: `cargo test -p erdps-agent test_tls_detection --lib`

## Known Warnings/Notes
- Unused imports in analyzer files may appear; safe to ignore or fix later.
- Some integration tests may fail due to SQLite database locks unrelated to network features.

## Next Steps
- Capture traffic on an interface using `EnhancedPcapAnalyzer::start_capture` with an optional BPF filter.
- Validate HTTPS/TLS detection on live traffic and collect SNI/ALPN in future iterations.