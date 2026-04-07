use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sysinfo::System;
use colored::*;

pub struct NetworkScanner;

impl NetworkScanner {
    pub fn scan_network() {
        println!("{}", "\n[ NETWORK SCANNER ] Listing Active Connections...".bright_cyan().bold());
        println!("{:<8} {:<25} {:<25} {:<10} {:<15} {:<20}", "PROTO", "LOCAL ADDRESS", "REMOTE ADDRESS", "PID", "PROCESS", "STATUS");
        println!("{:-<8} {:-<25} {:-<25} {:-<10} {:-<15} {:-<20}", "", "", "", "", "", "");

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let sockets_info = match get_sockets_info(af_flags, proto_flags) {
            Ok(si) => si,
            Err(e) => {
                println!("[!] Failed to get socket info: {}", e);
                return;
            }
        };

        let mut sys = System::new_all();
        sys.refresh_processes();

        for si in sockets_info {
            let mut local_addr = String::new();
            let mut remote_addr = String::new();
            let mut state = "UNKNOWN".to_string();
            let mut proto = "UNKNOWN";
            let mut suspicious = false;

            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_info) => {
                    proto = "TCP";
                    local_addr = format!("{}:{}", tcp_info.local_addr, tcp_info.local_port);
                    remote_addr = format!("{}:{}", tcp_info.remote_addr, tcp_info.remote_port);
                    state = tcp_info.state.to_string();
                    
                    if [4444, 6667, 3389, 1337].contains(&tcp_info.remote_port) {
                        suspicious = true;
                    }
                },
                ProtocolSocketInfo::Udp(udp_info) => {
                    proto = "UDP";
                    local_addr = format!("{}:{}", udp_info.local_addr, udp_info.local_port);
                    remote_addr = "*:*".to_string(); // UDP is connectionless
                    state = "Stateless".to_string();
                }
            }

            let pids = si.associated_pids;
            if pids.is_empty() {
                Self::print_row(proto, &local_addr, &remote_addr, "N/A", "System/Unknown", &state, suspicious);
            } else {
                for pid in pids {
                    let process_name = if let Some(process) = sys.process(sysinfo::Pid::from(pid as usize)) {
                        process.name().to_string()
                    } else {
                        "Unknown".to_string()
                    };

                    Self::print_row(proto, &local_addr, &remote_addr, &pid.to_string(), &process_name, &state, suspicious);
                }
            }
        }
        println!();
    }

    fn print_row(proto: &str, local: &str, remote: &str, pid: &str, process: &str, state: &str, suspicious: bool) {
        let mut row_color = "white";
        
        if suspicious {
            row_color = "red";
        } else if state == "Established" {
            row_color = "green";
        } else if process == "Unknown" {
            row_color = "yellow";
        }

        let formatted_row = format!("{:<8} {:<25} {:<25} {:<10} {:<15} {:<20}", 
            proto, 
            local.chars().take(24).collect::<String>(), 
            remote.chars().take(24).collect::<String>(), 
            pid, 
            process.chars().take(14).collect::<String>(), 
            state
        );

        match row_color {
            "red" => println!("{}", formatted_row.red().bold()),
            "green" => println!("{}", formatted_row.green()),
            "yellow" => println!("{}", formatted_row.yellow()),
            _ => println!("{}", formatted_row),
        }
    }
}
