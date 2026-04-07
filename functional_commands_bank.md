# Functional Commands Bank (Windows)

## Build and Run Agent
- Build release: `cargo build --release`
- Run agent (default features): `cargo run --release`
- Config override: edit `config.toml` or `config/agent.toml`

## IPC Client (Working)
- Status: `cargo run --bin ipc_client`
- Quarantine file: `cargo run --bin ipc_client -- quarantine ./test_story.txt`
- Custom server: `cargo run --bin ipc_client -- --server 127.0.0.1:7777`

## Debug and Validation
- Validate config: `cargo run --bin debug_config`
- Generate baseline config: `cargo run --bin generate_baseline_config`
- Debug IPC key/signature:
  - `cargo run --bin debug_key`
  - `cargo run --bin debug_signature`
  - `cargo run --bin debug_signature_sync`
  - `cargo run --bin debug_live_signature`

## YARA Tools
- Validate rules: `python validate_yara_rules.py`
- Minimal run with YARA: `cargo run --release --features yara`

## Feature Enablement Examples
- Disassembly (Capstone): `cargo run --release --features advanced-disassembly`
- Enhanced PCAP/TLS: `cargo run --release --features enhanced-pcap`
- Network monitoring: `cargo run --release --features network-monitoring`
- AI integration: `cargo run --release --features ai-integration`
- Telemetry stack: `cargo run --release --features telemetry`
- Windows service: `cargo build --release --features windows-service`

## Tests and Benchmarks
- Unit tests (lib): `cargo test --lib`
- Comprehensive tests: `cargo test --features comprehensive-testing`
- IPC benchmark: `cargo bench --bench ipc_benchmarks --features benchmarking`

## Common Troubleshooting
- Clean build: `cargo clean && cargo build --release`
- Check Npcap: `./verify_npcap.ps1`
- Adjust IPC port: set in `config.toml` and pass `--server` to clients