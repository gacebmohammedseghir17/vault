# ERDPS: Enterprise Ransomware Defense & Protection System

![ERDPS](https://img.shields.io/badge/Security-EDR-red.svg)
![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)

**ERDPS** is an enterprise-grade Endpoint Detection and Response (EDR) system specifically architected to detect, isolate, and roll back advanced ransomware attacks in real-time. ERDPS employs an "Absolute Zero" architecture that strictly separates User-Mode behavioral analysis from Ring 0 (Kernel) termination and containment, guaranteeing that threats are stopped in microseconds before significant data loss occurs.

---

## 🎯 Architecture: The "Absolute Zero" Model

ERDPS operates across a dual-layer architecture designed to mitigate TOCTOU (Time-of-Check to Time-of-Use) race conditions and prevent the EDR itself from being terminated by malware.

1. **C Minifilter Driver (Ring 0 - Kernel)**
   - **The Guillotine**: The driver natively hooks into the Windows I/O stack (`PreWrite`, `PreSetInformation`). It contains hardcoded rules for blocking known ransomware extensions (e.g., `.lockbit`, `.wncry`).
   - **Sliding Window I/O Rate Limiter**: The kernel tracks the speed of file modifications. If a single Process ID (PID) modifies more than 15 files within 50 milliseconds, the kernel instantly executes `ZwTerminateProcess`, effectively halting high-speed encryption loops.
   - **Asynchronous ALPC**: Instead of waiting for a user-mode decision (which is slow and prone to deadlocks), the kernel makes the kill decision instantly and fires an asynchronous ALPC message to the Rust agent to handle reporting and micro-rollbacks.

2. **Rust Agent (Ring 3 - User Mode)**
   - Operates as a highly resilient listener on the ALPC port (`\ERDPS_SentinelPort`).
   - Handles advanced deception techniques (Canaries), threat graphing, and post-kill forensic tasks like Surgical Micro-Rollback and SIEM telemetry forwarding.
   - Protected by `RtlSetProcessIsCritical` (BSOD trap) to ensure malware cannot kill the agent without crashing the OS, forcing threat actors into a lose-lose situation.

---

## 🧩 Core Components

### 1. ALPC Kernel Bridge (`src/kernel_bridge.rs`)
The nerve center of the Rust Agent. It connects to the C Kernel via Advanced Local Procedure Calls (ALPC) and runs an indestructible, auto-reconnecting `FilterGetMessage` listener loop. 
- **Reason 1**: Blocked Extension Write
- **Reason 2**: Blocked Extension Rename
- **Reason 3**: I/O Rate Limit Breach (Mass Encryption Halted)

### 2. Threat Graph / Executioner (`src/threat_graph.rs`)
Originally a complex lineage-tracking system, the Threat Graph has been refined to serve as the immediate User-Mode executioner. When it receives ETW (Event Tracing for Windows) detections or network canary alerts, it executes Ring 3 termination using native Windows APIs (`OpenProcess`, `TerminateProcess`) with strict Win32 error logging (e.g., `ERROR_ACCESS_DENIED`).

### 3. Surgical Micro-Rollback (`src/micro_rollback.rs`)
VSS (Volume Shadow Copy) is often deleted by ransomware. ERDPS utilizes a proprietary **Copy-on-Write (CoW) Vault**.
- The Kernel silently backs up the first write of any file to `C:\ERDPS_Vault\`.
- A JSONL ledger (`C:\ERDPS_Vault\ledger.json`) maps the malicious PID to the backed-up files.
- Upon process termination, `micro_rollback.rs` parses the ledger and surgically copies pristine `.bak` files back to their original paths.

### 4. Deception Manager (`src/deception_manager.rs`)
Active defense module designed to catch lateral movement and memory scraping.
- **Network Canary**: Binds a dummy listener to targeted ports (e.g., TCP 3389). If a local PID connects to this trap, it is immediately flagged with a lethal score and terminated.
- **Credential Canary**: Injects fake credentials into the Windows Credential Manager (`CredWriteW`). The Kernel monitors access to these credentials.

### 5. Active Defense & Process Hardening (`src/active_defense/mod.rs`)
- Implements `RtlSetProcessIsCritical` to harden the agent.
- Features a graceful exit handler (via `ctrlc`) that unhardens the process when shut down properly, preventing a system BSOD.
- Contains the `never_kill` policy gate to protect critical OS processes (`csrss.exe`, `lsass.exe`, `svchost.exe`).

### 6. SIEM Forwarder
An asynchronous, non-blocking MPSC queue that forwards JSON-serialized `SiemAlert` payloads via `reqwest` to enterprise SIEM dashboards, ensuring zero latency in the core EDR execution loops.

---

## 📦 Dependencies

ERDPS relies on high-performance and system-level Rust crates. Key dependencies include:

- **Windows API (`windows` & `winapi`)**: Deep integration with `Win32_Storage_InstallableFileSystems` (ALPC), `Win32_System_Threading` (Process Management), and `Win32_Security`.
- **Async & Concurrency**: `tokio`, `futures`, `rayon`, `crossbeam`, `parking_lot`.
- **Networking & Web**: `reqwest`, `axum`, `hyper`.
- **System Info & Forensics**: `sysinfo`, `capstone`, `iced-x86`, `yara-x`.
- **Serialization & Logging**: `serde`, `serde_json`, `bincode`, `tracing`, `flexi_logger`.
- **Cryptography**: `aes-gcm`, `argon2`, `ring`, `blake3`.

*(See `Cargo.toml` for the exhaustive list).*

---

## 🚀 How to Build and Run

### Prerequisites
- Windows 10/11 (64-bit).
- MSVC Toolchain for Rust (`x86_64-pc-windows-msvc`).
- Administrator privileges (required for ALPC, Process Hardening, and Ring 3 Termination).
- The ERDPS C Minifilter Driver must be loaded and running (`fltmc load erdps_driver`).

### Build
To build the agent as a standalone binary (statically linked CRT):
```powershell
# Set static CRT linking
$env:RUSTFLAGS="-C target-feature=+crt-static"

# Compile for release
cargo build --release
```

### Run
Launch the agent from an Administrator PowerShell terminal:
```powershell
.\target\release\erdps-agent.exe
```

---

## 🧪 Testing with True I/O Simulators

ERDPS includes highly realistic, multi-threaded ransomware simulators designed to stress-test the Kernel's 50ms Rate Limiter.

1. **Setup the Test Environment**:
   Run the setup script to generate 50 dummy files in your Music folder.
   ```powershell
   .\setup_test_env.ps1
   ```
   *(This creates `C:\Users\<User>\Music\Ransomware_Test_Zone` with dummy `.txt` files).*

2. **Run a Simulator**:
   Execute one of the simulators. They will spawn 50 concurrent threads to rapidly overwrite and rename the dummy files.
   ```powershell
   cargo run --bin lockbit_double_ext_sim
   cargo run --bin wannacry_crypto_sim
   ```

3. **Observe the Guillotine**:
   The ERDPS Agent will instantly catch the ALPC alert from the Kernel and print:
   `[CRITICAL] KERNEL RATE LIMITER TRIGGERED -> MASS ENCRYPTION HALTED ON PID XXXX`

---

## 🛡️ Evolution & History

ERDPS evolved through several critical architectural phases to address the realities of modern ransomware:
1. **The Synchronous Trap**: Initially attempted to block I/O synchronously from User-Mode via ALPC replies. *Abandoned* because waiting for User-Mode caused OS freezing and Deadlocks.
2. **The Threat Graph**: Utilized complex lineage scoring. *Abandoned* because it caused False Positive Loops (I/O Retry Storms) against safe processes like `msedge.exe`.
3. **The Targeted Freeze**: Implemented process/path whitelists. *Abandoned* because ignoring `\AppData\` blinded the EDR to WannaCry.
4. **Absolute Zero (Current)**: Realized that User-Mode TOCTOU (Time-of-Check to Time-of-Use) is fundamentally flawed against ransomware. Shifted 100% of blocking and termination to the Ring 0 Kernel Minifilter. The Rust agent was stripped down to a lightning-fast ALPC listener, Deception Manager, and SIEM forwarder.

---
*Developed by the ERDPS Team.*
