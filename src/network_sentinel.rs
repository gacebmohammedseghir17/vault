use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::thread;
use std::collections::HashMap;
use std::time::Duration;
use std::sync::{Arc, Mutex};

pub struct NetSentinel;

impl NetSentinel {
    // 🌐 START NETWORK MONITOR
    pub fn start_monitor() {
        thread::spawn(|| {
            println!("\x1b[35m[NETWORK] 🌐 NET SENTINEL ACTIVE (Anti-Worm/C2)\x1b[0m");
            
            // 1. Get All Interfaces
            let interfaces = datalink::interfaces();
            println!("\x1b[36m[DEBUG] Npcap detected {} interfaces:\x1b[0m", interfaces.len());

            // 2. DEBUG PRINT LOOP
            for iface in &interfaces {
                println!("   |-- Name: [{}] Up: {} Loop: {} IPs: {}", 
                    iface.name, 
                    iface.is_up(), 
                    iface.is_loopback(), 
                    iface.ips.len()
                );
            }

            // 3. Relaxed Selection Logic (Try to grab ANY non-loopback)
            let interface_opt = interfaces.into_iter()
                .find(|iface| !iface.is_loopback() && !iface.ips.is_empty()); // Removed is_up() check for now

            let interface = match interface_opt {
                Some(i) => i,
                None => {
                    println!("\x1b[31m[NETWORK] ❌ FAILURE: No suitable adapter found (Check Debug Output).\x1b[0m");
                    return;
                }
            };

            println!("\x1b[32m[NETWORK] ✅ Selected Interface: {}\x1b[0m", interface.name);

            // 2. Setup Connection Tracker (Re-using logic from previous version)
            let connection_tracker: Arc<Mutex<HashMap<String, u32>>> = Arc::new(Mutex::new(HashMap::new()));
            let tracker_clone = connection_tracker.clone();

            // Background cleaner (Resets counts every 5s for Double-Extortion sensitivity)
            thread::spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(5));
                    let mut tracker = tracker_clone.lock().unwrap();
                    tracker.clear();
                }
            });

            // 3. Open Channel
            let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    println!("\x1b[31m[NETWORK] ❌ Error: Unknown channel type.\x1b[0m");
                    return;
                },
                Err(e) => {
                    println!("\x1b[31m[NETWORK] ❌ Error starting capture: {}\x1b[0m", e);
                    return;
                }
            };

            // 4. Packet Loop (TUNED VERSION)
            loop {
                match rx.next() {
                    Ok(packet) => {
                        let packet = EthernetPacket::new(packet).unwrap();
                        if let Some(ip_header) = Ipv4Packet::new(packet.payload()) {
                            if let Some(tcp_header) = TcpPacket::new(ip_header.payload()) {
                                
                                let flags = tcp_header.get_flags();
                                let dest_port = tcp_header.get_destination();

                                // FILTER 1: Strict SYN Check
                                // We ONLY want 'SYN'. We do NOT want 'SYN + ACK' (Replies).
                                // pnet flags: SYN=0x02, ACK=0x10. We want exactly 0x02.
                                if flags == pnet::packet::tcp::TcpFlags::SYN {
                                    
                                    // FILTER 2: Whitelist Web Traffic (Reduce Noise)
                                    // Ransomware/Worms usually scan SMB (445), RDP (3389), or high ports.
                                    // We ignore standard web browsing ports.
                                    if dest_port == 80 || dest_port == 443 {
                                        continue;
                                    }

                                    let src = ip_header.get_source().to_string();
                                    
                                    let mut tracker = connection_tracker.lock().unwrap();
                                    let count = tracker.entry(src.clone()).or_insert(0);
                                    *count += 1;

                                    // FILTER 3: Higher Threshold & Spam Control
                                    // Alert if > 20 connections in 5s (Detecting low-and-slow exfiltration / double extortion)
                                    if *count > 20 && *count % 10 == 0 {
                                        println!("\x1b[31;1m[CRITICAL] Possible Data Exfiltration Detected (Double Extortion)! IP {} has {} rapid connections. Target Port: {}\x1b[0m", src, count, dest_port);
                                    }
                                }
                            }
                        }
                    },
                    Err(_) => continue,
                }
            }
        });
    }
}
