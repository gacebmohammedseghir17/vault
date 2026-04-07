# ERDPS: Enterprise Ransomware Defense & Protection System
## Technical Whitepaper & Operational Manual (v6.5)

---

### 1. Executive Summary
**ERDPS** is an enterprise-grade endpoint security solution designed to neutralize advanced ransomware and persistent threats. Unlike traditional AVs that rely solely on signatures, ERDPS employs a **Hybrid Defense Architecture** that combines:
1.  **Kernel-Level Monitoring**: A Minifilter driver (`ERDPS_Sentinel.sys`) intercepts file I/O and process creation in real-time.
2.  **Artificial Intelligence**: A dual-engine AI (Static N-Gram + Behavioral LSTM) analyzes threats pre-execution and during runtime.
3.  **Active Defense**: Autonomous countermeasures including process termination and Volume Shadow Copy (VSS) protection.

This document serves as a comprehensive guide for security architects, analysts, and operators.

---

### 2. System Architecture

The system is divided into two protection rings: **Kernel Mode** (Ring 0) and **User Mode** (Ring 3).

#### 2.1 Kernel Mode (The Sentinel Driver)
*   **Component**: `ERDPS_Sentinel.sys` (Minifilter Driver)
*   **Function**: Intercepts I/O requests (IRPs) before they reach the disk.
*   **Capabilities**:
    *   **Pre-Create Analysis**: Blocks file creation by known malicious processes.
    *   **Anti-Tamper**: Prevents renaming or deletion of decoy files (Honeypots).
    *   **Process Notification**: Alerts the User Mode Agent when a new process starts.

#### 2.2 User Mode (The Agent)
The Rust-based Agent (`erdps-agent.exe`) acts as the brain of the operation.

| Module | Responsibility |
| :--- | :--- |
| **Kernel Bridge** | Manages the communication port (`\ERDPSPort`) to receive alerts from the driver. |
| **Neural Engine** | Runs AI inference. Uses `LightGBM` (Static) and `ONNX/LSTM` (Behavioral) models. |
| **Intel Manager** | Manages the YARA signature database, performing smart deduplication and strict validation. |
| **Active Defense** | Executes mitigation actions (Kill Switch, Snapshot) when a high-confidence threat is detected. |
| **Live Hunter** | Polls external Threat Intel APIs (`ransomware.live`) to fetch real-time C2 and group data. |
| **Forensic Pipeline** | A multi-stage analysis engine for deep inspection of suspicious files. |

---

### 3. Core Engines & Features

#### 🧠 Neural Engine (V6 Architecture)
*   **Static Brain**: Uses an **N-Gram** model (`static_model_2024.onnx`) to analyze the raw byte structure of a file. It detects malicious patterns without running the code.
*   **Behavioral Brain**: Uses an **LSTM (Long Short-Term Memory)** model to analyze sequences of system calls (e.g., `OpenProcess` -> `VirtualAlloc` -> `WriteProcessMemory`).

#### 🔬 Forensic Pipeline (Multi-Layer Analysis)
When a file is scanned, it passes through 6 distinct layers:
1.  **Cryptographic Hashing**: SHA256 calculation.
2.  **Entropy Analysis**: Calculates Shannon Entropy to detect packed/encrypted payloads (High Entropy > 7.2).
3.  **PE Parsing**: Extracts headers, sections, and imports using `goblin`.
4.  **YARA Engine**: Scans against `master_threats.yara` (80,000+ rules).
5.  **Heuristic Analysis**: Scans stack strings and imports for capabilities (e.g., "Network C2", "Injection").
6.  **AI Verdict**: The Neural Engine provides a final probability score (0.0 - 1.0).

#### 🛡️ Active Defense
*   **Kill Switch**: Uses `taskkill /F /PID <id>` to immediately terminate confirmed threats.
*   **Shadow Defender**: Triggers `vssadmin create shadow /for=C:` to instantly snapshot files when ransomware behavior (e.g., mass rename) is detected.
*   **Yara Forge**: Automatically converts live threat intelligence (JSON) into compilable YARA rules.

---

### 4. Operational Guide

#### 4.1 Prerequisites
*   **OS**: Windows 10/11 or Server 2019+ (x64).
*   **Driver**: `ERDPS_Sentinel.sys` must be loaded (`sc start ERDPS_Sentinel`).
*   **Dependencies**: `static_model_2024.onnx`, `behavioral_model.onnx`, and `rules/` directory.

#### 4.2 Mode 1: Sentinel (Autonomous Protection)
*   **Command**: Select Option `[1]` in the main menu.
*   **Behavior**: The agent enters a blocking loop, monitoring kernel events.
*   **Output**:
    *   <span style="color:red">**[THREAT]**</span>: Process Killed (Honeypot Trigger).
    *   <span style="color:yellow">**[BEHAVIOR]**</span>: Suspicious Access (AI Score > 0.7).
    *   <span style="color:green">**[DEFENSE]**</span>: Ransomware Blocked (Rename/Delete attempt).

#### 4.3 Mode 2: Forensic Toolkit (God Mode CLI)
*   **Command**: Select Option `[2]` in the main menu.
*   **Interface**: A specialized shell for manual analysis.

**CLI Commands:**
| Command | Usage | Description |
| :--- | :--- | :--- |
| **`scan`** | `scan <path>` | Runs the Forensic Pipeline on a specific file. Generates reports. |
| **`compile`** | `compile rules` | Harvests `.yar` files from `rules/`, deduplicates, and compiles `master_threats.yara`. |
| **`reload`** | `reload` | Hot-reloads the Pipeline and Rules without restarting the agent. |
| **`help`** | `help` | Shows available commands. |

---

### 5. Reporting & Output

#### 5.1 Console Output
The CLI uses color-coded output for immediate feedback:
*   **RED**: MALICIOUS (Confidence > 85% or YARA Match).
*   **YELLOW**: SUSPICIOUS (High Entropy or AI Score > 60%).
*   **GREEN**: CLEAN.

#### 5.2 Evidence Files
Every scan generates two files in the `reports/` folder:

1.  **JSON Report** (`report_TIMESTAMP_VERDICT.json`)
    *   Full structural data (Hashes, Strings, Sections).
    *   Ideal for ingestion into SIEMs (Splunk, ELK).

2.  **HTML Dashboard** (`report_TIMESTAMP_VERDICT.html`)
    *   **"God Mode" UI**: A self-contained, Cyberpunk-themed dashboard.
    *   **Visuals**: Badges for threats, risk score meters, and readable tables.
    *   **Portability**: Single file, no external CSS/JS dependencies.

---

### 6. Configuration & Development

#### Directory Structure
```
ERDPS/
├── erdps-agent.exe        # Main Binary
├── static_model_2024.onnx # AI Model (Static)
├── behavioral_model.onnx  # AI Model (Dynamic)
├── rules/                 # YARA Rule Repository
│   ├── master_threats.yara # Compiled Database
│   └── ... (.yar files)
├── reports/               # Output Directory
└── ERDPS_Sentinel.sys     # Kernel Driver
```

#### Build Instructions
To compile from source (requires Rust Toolchain & C++ Build Tools):
```powershell
# 1. Navigate to agent directory
cd agent

# 2. Build Release Binary
cargo build --release

# 3. Output located at target/release/erdps-agent.exe
```

#### Adding New Rules
1.  Place `.yar` files in the `rules/` folder.
2.  Start the Agent -> Option `[2]`.
3.  Run `compile rules`.
4.  Run `reload`.

---

### 7. Troubleshooting

*   **"[ERROR] Driver not found"**: Ensure `ERDPS_Sentinel.sys` is installed and running (`sc query ERDPS_Sentinel`). The agent needs Admin privileges.
*   **"Master YARA DB not found"**: Run `compile rules` to generate the database for the first time.
*   **"Toxic Rule Dropped"**: The Intel Manager found a rule with a Regex that is too complex/large. It was automatically skipped to prevent crashing.
*   **"Access Denied" during Build**: Close any running instances of `erdps-agent.exe` before rebuilding.
