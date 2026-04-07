use std::fs::{self, File};
use std::io::Write;
use std::thread;
use std::time::Duration;
use std::path::Path;

fn main() {
    println!("============================================");
    println!("   RANSOMWARE SIMULATOR (SAFE MODE)         ");
    println!("   Target: C:\\ERDPS_Simulation_Zone        ");
    println!("============================================");

    // 1. Setup the "Shooting Range"
    let target_dir = "C:\\ERDPS_Simulation_Zone";
    if !Path::new(target_dir).exists() {
        fs::create_dir_all(target_dir).expect("Failed to create simulation zone");
    }

    println!("\n[!] STARTING IN 5 SECONDS. MAKE SURE SENTINEL IS RUNNING!");
    thread::sleep(Duration::from_secs(5));

    // 2. Trigger Telemetry (Massive I/O)
    println!("[*] ACT 1: Simulating Encryption (High I/O)...");
    let dummy_data = vec![0u8; 5 * 1024 * 1024]; // 5MB Chunk
    
    for i in 1..=50 {
        let file_path = format!("{}\\{}.enc", target_dir, i);
        print!("    -> Encrypting: {} ... ", file_path);
        
        if let Ok(mut f) = File::create(&file_path) {
            f.write_all(&dummy_data).unwrap();
            println!("DONE");
        }
        // Small delay to simulate processing, but fast enough to trigger 50MB/s alert
        thread::sleep(Duration::from_millis(50));
    }

    // 3. Trigger Minefield (The Trap)
    println!("\n[*] ACT 2: Touching Honeyfiles...");
    let trap_file = "C:\\ERDPS_Honey\\passwords.xlsx";
    
    if Path::new(trap_file).exists() {
        println!("    -> ATTEMPTING to read bait: {}", trap_file);
        match fs::read(trap_file) {
            Ok(_) => println!("    -> [FAIL] I read the file. Agent did not stop me."),
            Err(_) => println!("    -> [SUCCESS?] Access failed (Maybe I am frozen?)"),
        }
    } else {
        println!("    -> [ERR] Honeyfile not found. Did Sentinel deploy the minefield?");
    }

    println!("\n[*] SIMULATION COMPLETE. Waiting...");
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
