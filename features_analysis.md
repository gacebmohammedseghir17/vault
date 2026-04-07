# ERDPS Features Analysis

## Overview
- Purpose: Map all major features, their status, gating, and file references.
- Status Keys: ✅ 100% Functional | ⚠️ Partially Functional | ❌ Non-Functional/Stubs | 🔒 Feature-Gated

## Core Agent
- ✅ Agent Service (entrypoint)
  - Files: `src/main.rs`, `src/core/agent.rs`, `src/lib.rs`, `src/logger.rs`, `src/core/config.rs`
  - Notes: Runs, loads config, starts IPC server and monitors.
- ✅ Configuration Management
  - Files: `src/config/mod.rs`, `src/config/agent_config.rs`, `config/agent.toml`, `config.toml`
  - Notes: Parsing works; `debug_config` validates.
- ⚠️ Telemetry & Metrics
  - Files: `src/monitoring/metrics.rs`, `src/metrics/*`, `prometheus.yml`
  - Gating: `metrics` feature (enabled in default) / `telemetry` feature (optional)
  - Notes: Exposes metrics; dashboard wiring is limited.

## IPC and Commands
- ✅ IPC Server
  - Files: `src/ipc.rs`
  - Notes: Server listens on `127.0.0.1:7777` (configurable); HMAC signing.
- ✅ IPC Client (functional)
  - Files: `src/bin/ipc_client.rs`
  - Notes: Status and quarantine commands work.
- ⚠️ Other IPC utilities (port mismatch)
  - Files: `src/bin/simple_ipc_test.rs`, `test_dashboard_client.rs`, `src/bin/test_alert_delivery.rs`
  - Notes: Hardcoded `7778`; agent default is `7777`.

## Detection Engines
- ⚠️ YARA Detection
  - Files: `src/detection/yara_engine.rs`, `src/detection/yara_rules.rs`, `rules/`
  - Gating: `yara` feature (enabled by default)
  - Notes: Rule compilation partly succeeds (e.g., 1/2). Detection pipeline active.
- ⚠️ Behavioral Analysis
  - Files: `src/behavioral/*`, `src/monitor/enhanced_api_monitor.rs`
  - Gating: `behavioral-analysis` (enabled by default), `api-hooking`
  - Notes: Interfaces present; runtime coverage depends on Windows APIs/ETW setup.
- ⚠️ Heuristic & Pattern Matching
  - Files: `src/detection/heuristic.rs`, `src/detection/pattern_matcher.rs`
  - Notes: Works with simple patterns; limited scoring.
- ⚠️ Enterprise Detection Orchestrator
  - Files: `src/detection/enterprise_engine.rs`, `src/detection/integration.rs`
  - Notes: Wiring present; some modules stubbed.

## Mitigations & Quarantine
- ✅ File Quarantine & Restore
  - Files: `src/mitigations.rs`, `quarantine/`
  - Notes: Atomic move to quarantine, manifest, restore functionality. Tested.
- ⚠️ Network Quarantine
  - Files: `src/response/network_quarantine.rs`
  - Notes: Engine scaffold; limited integration.
- ⚠️ Policy-driven Response
  - Files: `src/response/policy_engine.rs`
  - Notes: Triggers defined; automation policies incomplete.

## Filesystem & Integrity
- ✅ Filesystem Monitor
  - Files: `src/filesystem/monitor.rs`, `src/monitor/fs.rs`
  - Notes: Starts and watches common paths; integrates with detection.
- ⚠️ File Integrity & Process Watch
  - Files: `src/integrity/*`
  - Notes: Hashing and process watch present; limited enforcement.

## Network Monitoring & Threat Intel
- 🔒 Enhanced PCAP/TLS/Cert Analysis
  - Files: `src/network/*`
  - Gating: `network-monitoring`, `enhanced-pcap` (pcap/pnet/x509-parser)
  - Notes: Requires Npcap/libpcap on Windows; otherwise disabled.
- ⚠️ Beacon/Exfiltration Detection
  - Files: `src/network/beacon_detector.rs`, `src/network/exfiltration_detector.rs`
  - Notes: Logic present; depends on packet capture enablement.
- ⚠️ Threat Intelligence
  - Files: `src/threat_intel/*`, `network_intelligence.db`
  - Notes: Enrichment stubs; local DB updates limited.

## Advanced EDR Capabilities
- 🔒 Disassembly Engine (Capstone)
  - Files: `src/disassembly/capstone_engine.rs`, `src/disassembly/mod.rs`, `src/disassembly/*`
  - Gating: `advanced-disassembly` (capstone/capstone-sys)
  - Notes: Stubbed without feature; full x86/x64 support when enabled.
- 🔒 AI Integration (EMBED/OLLAMA)
  - Files: `src/ai/*`, `models/ember_model.onnx`
  - Gating: `ai-integration` (ORT, ndarray)
  - Notes: Requires ONNX runtime and model placement; otherwise inactive.
- ⚠️ Memory Forensics
  - Files: `src/memory/*`
  - Gating: `memory-forensics` (enabled by default)
  - Notes: PE/ELF parsing utilities; limited end-to-end flows.

## Observability & Dashboard
- ⚠️ Prometheus/Telemetry
  - Files: `src/observability/*`, `src/monitoring/*`, `prometheus.yml`, `grafana/`
  - Gating: `metrics`/`telemetry`
  - Notes: Metrics emit; dashboard setup requires external stack.
- ❌ HTTP Dashboard UI
  - Files: `src/enterprise/dashboard.rs`, `src/observability/dashboard.rs`
  - Notes: Conceptual; no functional web UI.

## Windows Service & Identity
- 🔒 Windows Service Mode
  - Files: `src/service.rs`
  - Gating: `windows-service`
  - Notes: Service install/start/stop interfaces; requires feature enable and admin.
- ⚠️ Identity Hardening
  - Files: `src/identity/*`
  - Gating: `identity-hardening`/`endpoint-hardening`
  - Notes: Monitors LSASS/PowerShell; enforcement limited.

## Correlation, Scoring, and Reports
- ❌ Threat Scoring (ML)
  - Files: `src/correlation/threat_scorer.rs`
  - Notes: Model/scaler missing; not functional.
- ⚠️ AI-YARA Correlation
  - Files: `src/correlation/ai_yara_correlator.rs`, `src/correlation/correlation_engine.rs`
  - Notes: Pipeline hooks present; outputs limited.
- ⚠️ Export/Report Interfaces
  - Files: `src/reports/*`, `src/ipc_interface.rs`
  - Notes: Export IPC types defined; end-to-end flows partial.

## Testing & Validation
- ⚠️ Tests and Benches
  - Files: `src/bin/test_*`, `tests/*`, `benches/ipc_benchmarks.rs`
  - Notes: Several fail due to port/signature mismatches; client `ipc_client` works.

## Feature Gating Summary (Cargo Features)
- Default enabled: `basic-detection`, `metrics`, `yara`, `validation-framework`, `advanced-logging`, `behavioral-analysis`, `automated-response`, `network-monitoring`, `memory-forensics`, `reqwest`
- Optional enable:
  - `advanced-disassembly` → Capstone disassembler
  - `ai-integration` → ORT/ONNX-based AI
  - `enhanced-pcap` → Deep packet/TLS/X509 analysis
  - `telemetry` → OpenTelemetry/Prometheus integration
  - `windows-service` → Windows service hosting
  - `super-yara`, `advanced-edr` → Bundle feature sets

## Quick Reality Check
- Fully usable today: Agent service, IPC client, filesystem monitoring, quarantine.
- Works with limitations: YARA detection, metrics/telemetry, behavioral/network analysis.
- Requires enablement/setup: Disassembly (Capstone), AI integration (ORT/ONNX), enhanced PCAP, Windows service.
- Not functional: HTTP dashboard UI, ML threat scoring model.