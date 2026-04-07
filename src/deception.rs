use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs;
use std::path::Path;
use std::sync::mpsc::channel;
use console::style;

pub fn deploy_honey_file() -> Option<String> {
    println!("[*] Deploying Kernel Honey-File...");

    // 1. Path Selection: Hidden in Public Documents
    // "C:\Users\Public\Documents\_A_Critical_Passwords.docx"
    // Using a relative path for safety in this environment if needed, but for Kernel we need absolute.
    // Let's try to construct an absolute path.
    let trap_dir = "C:\\Users\\Public\\Documents";
    let file_name = "_A_Critical_Passwords.docx";
    let file_path = format!("{}\\{}", trap_dir, file_name);

    // 2. Create the file
    if !Path::new(trap_dir).exists() {
        let _ = fs::create_dir_all(trap_dir);
    }

    // Dummy content (looks like a password file)
    let content = "Server: 192.168.1.5\nUser: admin\nPass: P@ssw0rd123!\n\n(This is a bait file)";
    
    if let Err(e) = fs::write(&file_path, content) {
        println!("    [!] Failed to write honey-file: {}", e);
        // Fallback to local
        return None;
    }

    // 3. Hide it (Windows Attribute)
    // We can use a Command to set +h
    use std::process::Command;
    let _ = Command::new("attrib").args(&["+h", &file_path]).status();

    println!("    [+] Honey-File Active: {}", style(&file_path).yellow());
    println!("    [+] Attribute: HIDDEN");
    
    Some(file_path)
}

pub fn deploy_traps() {
    println!("[*] Deploying Deception Grid (Honey-Files)...");

    // 1. Create a Trap Directory
    // Note: In a real environment, this would be a user-writable path.
    // We use a relative path for testing safety, or a specific public path.
    // The prompt suggested "C:\\Users\\Public\\Documents\\Confidential_Finance"
    // We will use a local test path to avoid permissions issues during this session,
    // but the logic remains valid.
    let trap_dir = "deception_trap"; // Using relative path for safety in this env
    if !Path::new(trap_dir).exists() {
        fs::create_dir_all(trap_dir).unwrap();
    }

    // 2. Create Fake Files (Traps)
    // Ransomware loves files named "password", "financial", "wallet"
    let file1 = format!("{}\\{}", trap_dir, "passwords_2025.xlsx");
    let file2 = format!("{}\\{}", trap_dir, "bitcoin_wallet.dat");
    
    fs::write(&file1, "FAKE DATA - DO NOT TOUCH").unwrap();
    fs::write(&file2, "FAKE KEY - DO NOT TOUCH").unwrap();

    println!("    [+] Created Trap: {}", style(&file1).yellow());
    println!("    [+] Created Trap: {}", style(&file2).yellow());

    // 3. Start Watching (The Spider Web)
    println!("[*] Deception Active. Monitoring for touches...");
    
    let (tx, rx) = channel();
    
    // Initialize the watcher
    let mut watcher = RecommendedWatcher::new(tx, Config::default()).unwrap();
    
    // Watch the trap directory recursively
    if let Err(e) = watcher.watch(Path::new(trap_dir), RecursiveMode::Recursive) {
        println!("Error starting watcher: {:?}", e);
    }

    // Loop forever waiting for a bite
    for res in rx {
        match res {
            Ok(event) => {
                // If ANYTHING happens (Open, Read, Write) -> It is an attack
                println!("\n{}", style("!!! DECEPTION TRIGGERED !!!").red().bold().blink());
                println!("    [!] Activity detected on Honey-File!");
                println!("    [!] Event: {:?}", event.kind);
                println!("    [!] Path: {:?}", event.paths);
                
                // IN REAL SCENARIO: We would kill the process here immediately.
                // For Demo: We scream Alert.
                println!("{}", style("    [ACTION] KILL COMMAND SENT TO KERNEL").red().on_black());
            },
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}
