# NotPetya Locker Simulator

## 1. How the Real Ransomware Works
NotPetya (2017) is widely considered one of the most devastating cyberattacks in history. While it masqueraded as ransomware, it was actually a destructive wiper malware deployed by state-sponsored actors.
1. **Wiper, Not Ransomware:** It did not have a mechanism to decrypt files even if the ransom was paid. Its sole purpose was to permanently destroy data.
2. **MBR Overwrite:** Instead of just encrypting files one by one, NotPetya overwrote the Master Boot Record (MBR) and the Master File Table (MFT) of the victim's hard drive.
3. **Forced Reboot:** After destroying the boot sector, it forced a blue screen or reboot, leaving the machine completely unbootable, displaying a fake `chkdsk` screen followed by a ransom note.
4. **Lateral Movement:** Like WannaCry, it used EternalBlue and credential dumping (Mimikatz) to spread rapidly across networks.

## 2. How the Simulator Replicates It
The `notpetya_locker_sim.rs` simulates the destructive, system-level behavior of a wiper masquerading as ransomware:
- **System Tool Abuse:** It aggressively executes `vssadmin delete shadows /all /quiet` to destroy shadow copies.
- **Backup Destruction:** It executes `wbadmin delete catalog -quiet` to destroy Windows Backup catalogs.
- **Ring 0 / MBR Access:** It actively attempts to open a raw handle to `\\.\PhysicalDrive0` (the physical hard drive). This simulates the exact access required to overwrite the MBR, a highly suspicious action for any user-mode application.
- **Ransom Note Drop:** It dynamically resolves the `%USERPROFILE%\Desktop` path and drops a `README_LOCKED.txt` file, mimicking the psychological aspect of the attack.
- **Stealth:** It disguises itself as a "Windows Boot Manager Setup" in terminal output to avoid basic string-matching defenses.

## 3. How it is Coded in Rust
- **Process Spawning:** Uses `std::process::Command` to execute the system-level destruction tools (`vssadmin` and `wbadmin`). The EDR's behavioral engine must detect these child processes, trace them back to the simulator (Parent PID), and kill the parent.
- **Raw Device Access:** Uses `std::fs::File::open("\\\\.\\PhysicalDrive0")`. Opening raw physical drives in Windows requires Administrator privileges and is a massive red flag that the EDR's Kernel bridge or API hooking should intercept.
- **Environment Variables:** Uses `std::env::var("USERPROFILE")` to dynamically locate the victim's Desktop, rather than hardcoding paths.
- **Sustained Execution:** Concludes with `std::thread::sleep(Duration::from_secs(20))` to prevent the process from terminating before the EDR can capture its memory dump and execute `ProcessFreezer::freeze(pid)`.
