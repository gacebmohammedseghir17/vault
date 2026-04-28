# LockBit Double Extortion Simulator

## 1. How the Real Ransomware Works
LockBit is one of the most prolific Ransomware-as-a-Service (RaaS) operations in the world. It is famous for its "Double Extortion" tactic:
1. **Data Exfiltration:** Before encrypting anything, LockBit stealthily uploads sensitive victim data to a remote Command & Control (C2) server. If the victim refuses to pay for the decryption key, the attackers threaten to leak the stolen data publicly.
2. **Shadow Copy Deletion:** It executes `vssadmin.exe delete shadows /all /quiet` to destroy Windows volume shadow copies, preventing easy system restoration.
3. **High-Speed Encryption:** It uses highly optimized multithreaded encryption (often ChaCha20 or AES) to lock files rapidly.
4. **Extension Mutation:** It appends a specific extension (e.g., `.lockbit`) to the encrypted files.

## 2. How the Simulator Replicates It
The `lockbit_double_ext_sim.rs` perfectly mimics this attack chain to test the EDR:
- **Stealth / Masquerading:** It masks its terminal output to look like a benign `Windows Service Update Tool`, testing if the EDR relies too heavily on static strings.
- **Admin Tool Abuse:** It spawns a child process executing the exact `vssadmin` command used by real LockBit.
- **Simulated Exfiltration:** It establishes a TCP connection (`127.0.0.1:9999`) and sends HTTP GET requests containing data identifiers, mirroring the network signature of data theft.
- **High-Entropy Encryption:** Instead of writing dummy text, it generates 500KB blobs of pure random data to mathematically mimic the high Shannon Entropy of encrypted files.
- **Extension Mutation:** It aggressively renames the `.dat` blobs to `.lockbit`.
- **Canary Deletion:** It specifically targets the `wallet.dat` honeypot file for deletion.

## 3. How it is Coded in Rust
- **Process Spawning:** Uses `std::process::Command` to execute `cmd /C vssadmin...`. The EDR's behavioral engine must detect this child process, trace it back to the simulator (Parent PID), and kill the parent.
- **Randomness (Entropy):** Uses the `rand::Rng` crate. `rng.fill(&mut buffer[..])` fills a `vec![0u8; 500 * 1024]` with random bytes. When written to disk via `File::write_all`, this triggers the EDR's `HIGH_ENTROPY_WRITE` alert (Alert 10).
- **Network I/O:** Uses `std::net::TcpStream` to fire off network packets, triggering the Double-Extortion network sentinel if done too rapidly.
- **Sustained Execution:** Implements `std::thread::sleep(Duration::from_secs(20))` at the end. This keeps the process alive in RAM so the EDR's `ProcessFreezer` and `MiniDumpWriteDump` can successfully execute without encountering `NTSTATUS: -1073741558` (Process Terminated).
