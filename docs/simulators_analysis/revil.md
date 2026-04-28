# REvil RaaS Dropper Simulator

## 1. How the Real Ransomware Works
REvil (also known as Sodinokibi) operated as a highly lucrative Ransomware-as-a-Service (RaaS) group. They were notorious for targeting large corporations (like Kaseya) and using "Living Off The Land" (LOLBin) techniques.
1. **LOLBin Abuse:** Attackers often gain access via compromised credentials or software vulnerabilities, then drop a payload using built-in Windows tools like `cmd.exe` or `powershell.exe`.
2. **Stealth Execution:** The dropper usually runs entirely in memory or spawns hidden background processes, downloading the actual encryptor payload dynamically.
3. **High-Speed Encryption:** Once downloaded, the payload encrypts the disk with Salsa20 and Curve25519 algorithms.
4. **Custom Extensions:** Often uses unique, randomized extensions (like `.revil`) for every victim.

## 2. How the Simulator Replicates It
The `revil_raas_sim.rs` focuses on the stealth and LOLBin evasion aspects of the REvil infection chain:
- **Stealth Injection:** It spawns a completely hidden child instance of `cmd.exe` that executes a `powershell.exe` command with `-ExecutionPolicy Bypass` and `-WindowStyle Hidden`.
- **Telemetry Evasion:** By masking itself as a "Windows Diagnostics Tool," it attempts to avoid static analysis.
- **Payload Execution:** Instead of dropping a real payload, the Rust code writes 500KB blobs of pure random data to `.tmp` files, simulating the extraction of the malicious payload.
- **Encryption:** It mass-renames the `.tmp` files to `.revil`, completing the encryption simulation.

## 3. How it is Coded in Rust
- **Process Creation Flags:** The most critical part of this simulator is its use of `std::os::windows::process::CommandExt`. It applies the `CREATE_NO_WINDOW` (0x08000000) flag to `std::process::Command::new("cmd")`. This makes the execution completely invisible to the user.
- **LOLBin Testing:** The EDR's Active Defense whitelist specifically must NOT include `cmd.exe` or `powershell.exe`. If those are whitelisted, the EDR will fail to kill this simulator's parent process.
- **Entropy Generation:** Uses `rand::thread_rng().fill(&mut buffer[..])` to create 500KB of random data per file, guaranteeing the Shannon Entropy exceeds the EDR's 7.5 threshold for `HIGH_ENTROPY_WRITE`.
- **Extension Mutation:** Uses `fs::rename` to rapidly change `.tmp` to `.revil`.
- **Sustained Execution:** Concludes with `std::thread::sleep(Duration::from_secs(20))` to prevent the process from terminating before the EDR can capture its memory dump and execute `ProcessFreezer::freeze(pid)`.
