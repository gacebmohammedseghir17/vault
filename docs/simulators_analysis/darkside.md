# DarkSide Doxware Simulator

## 1. How the Real Ransomware Works
DarkSide is infamous for the 2021 Colonial Pipeline attack. It is highly targeted, "big game hunting" ransomware.
1. **Double Extortion Focus:** Unlike basic lockers, DarkSide aggressively exfiltrates terabytes of sensitive data *before* encrypting the victim's machines. They use the threat of releasing this data ("doxware") as primary leverage.
2. **Low-and-Slow Exfiltration:** They often use legitimate tools (like Rclone or MegaSync) to slowly siphon data out over days or weeks, making it harder for basic firewalls to detect massive spikes in traffic.
3. **Encryption:** After the data is stolen, they execute highly efficient encryption algorithms to lock the systems down.

## 2. How the Simulator Replicates It
The `darkside_doxware_sim.rs` focuses heavily on the Double Extortion (data theft) aspect of the attack:
- **Massive Network Activity:** It interleaves high-speed file creation with rapid HTTP GET requests to a local sinkhole (`127.0.0.1:9999`). This simulates the aggressive data synchronization and exfiltration to a C2 server.
- **Doxware Behavior:** It mimics the process of staging files for exfiltration (creating `backup_vol_{i}.dat` files).
- **Stealth:** It disguises itself as a "Windows Backup Optimizer" in terminal output to avoid basic string-matching defenses.
- **Encryption Phase:** After "exfiltration," it mass-renames the staged data files to `.darkside`.

## 3. How it is Coded in Rust
- **Network Exfiltration Loop:** The simulator uses `std::net::TcpStream::connect("127.0.0.1:9999")` inside a `for i in 0..50` loop. It rapidly writes `GET /sync_blob?id={i} HTTP/1.1\r\n` to the stream. This rapid succession of SYN packets is explicitly designed to trigger the EDR's Double-Extortion Network Sentinel (which looks for >20 connections in 5 seconds).
- **Entropy Generation:** Uses `rand::thread_rng().fill(&mut buffer[..])` to create 500KB of random data per file, triggering the EDR's Shannon Entropy sensors.
- **Dynamic Extension Heuristics:** Uses `std::fs::rename` to rapidly mutate extensions from `.dat` to `.darkside`. This triggers the EDR's Mass Extension Mutation sensor.
- **Sustained Execution:** Concludes with `std::thread::sleep(Duration::from_secs(20))` to prevent the process from terminating before the EDR can capture its memory dump and execute `ProcessFreezer::freeze(pid)`.
