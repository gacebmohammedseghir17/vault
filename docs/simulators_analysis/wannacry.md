# WannaCry Crypto Simulator

## 1. How the Real Ransomware Works
WannaCry gained notoriety in 2017 as a self-propagating worm that caused billions of dollars in damage globally.
1. **Worm Capabilities:** It spreads via the EternalBlue SMB exploit, compromising unpatched Windows machines across networks without user interaction.
2. **Mass Encryption:** It scans for common file extensions (documents, pictures, databases) and encrypts them using RSA and AES.
3. **Extension Mutation:** It drops a `.WCRY` extension on all encrypted files.
4. **Data Access:** It actively searches for sensitive files like passwords and Bitcoin wallets.

## 2. How the Simulator Replicates It
The `wannacry_crypto_sim.rs` reproduces the rapid file destruction behavior:
- **Mass File Modification:** It rapidly writes 100 high-entropy blobs of 500KB each to the local disk, simulating the destructive encryption loop.
- **Extension Mutation:** It renames all the encrypted files, appending the infamous `.WCRY` extension.
- **Honeytoken Reading:** Unlike lockers that only overwrite, WannaCry accesses sensitive files to steal credentials or keys. The simulator actively reads `C:\Users\Public\passwords.txt`.
- **Stealth:** It disguises itself as a "Windows Component Updater" in terminal output to avoid basic string-matching defenses.

## 3. How it is Coded in Rust
- **Disk Thrashing Loop:** Uses a `for i in 0..100` loop combined with `std::fs::File::create` and `write_all`. The buffer is filled with pure entropy using `rand::thread_rng().fill(&mut buffer[..])`. This triggers the EDR's `HIGH_ENTROPY_WRITE` (Alert 10).
- **Dynamic Extension Heuristics:** Uses `std::fs::rename` in a rapid loop. This triggers the EDR's Mass Extension Mutation sensor (where `new_ext != old_ext` across multiple files).
- **Honeytoken Trap:** Uses `File::open` and `read_to_string()` on a known EDR Canary. The EDR's Kernel bridge is designed to intercept this specific `Read` event and sever the simulator's internet connection (`engage_network_isolation`), preventing exfiltration.
- **Memory Residency:** A final `std::thread::sleep(Duration::from_secs(20))` ensures the EDR has ample time to freeze the threads (`ProcessFreezer::freeze(pid)`) and execute a full `MiniDumpWriteDump` before the simulator exits gracefully.
