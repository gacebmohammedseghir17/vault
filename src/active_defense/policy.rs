use std::sync::atomic::Ordering;
use crate::active_defense::ActiveDefense;

// Helper to get process name without depending on binary crate
fn get_process_name(pid: u32) -> String {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        process.name().to_string()
    } else {
        String::from("Unknown")
    }
}

fn get_process_path(pid: u32) -> String {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default()
    } else {
        String::from("Unknown")
    }
}

fn get_parent_pid(pid: u32) -> Option<u32> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes();
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        process.parent().map(|p| p.as_u32())
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ActionPlan {
    LogOnly,
    Contain,
    Kill,
    StorylineKill,
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub source: &'static str,
    pub pid: u32,
    pub reason: u32,
    pub file_path: String,
    pub metadata: Option<String>,
}

pub struct PolicyGate;

impl PolicyGate {
    pub fn decide(signal: &Signal, requested_action: ActionPlan) -> ActionPlan {
        // 1. Mode Restrictions
        let sentinel_active = std::env::var("SENTINEL_UI_ACTIVE").unwrap_or_else(|_| "false".to_string()) == "true";
        if !sentinel_active {
            return ActionPlan::LogOnly;
        }

        // 2. Profile Restrictions
        let profile = std::env::var("ERDPS_PROFILE").unwrap_or_else(|_| "Production".to_string());
        if profile == "Production" {
            if signal.source == "IoHunter" || signal.source == "HookHunter" || signal.source == "GhostHunter" {
                return ActionPlan::LogOnly;
            }
        }

        // 3. Protected Process List
        let process_name = get_process_name(signal.pid).to_lowercase();
        let never_kill = [
            "system", "csrss.exe", "smss.exe", "wininit.exe", "lsass.exe", "winlogon.exe",
            "svchost.exe", "services.exe", "explorer.exe", "erdps-agent.exe", "erdps_agent.exe", "spoolsv.exe"
        ];
        let boundary_only = [
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"
        ];
        
        if never_kill.contains(&process_name.as_str()) {
            return ActionPlan::LogOnly;
        }

        // Reason 13 Log-only check
        if signal.reason == 13 {
            return ActionPlan::LogOnly;
        }

        // 4. Parent Boundary List (Stop storyline escalation)
        if requested_action == ActionPlan::StorylineKill {
            if let Some(ppid) = get_parent_pid(signal.pid) {
                let parent_name = get_process_name(ppid).to_lowercase();
                if never_kill.contains(&parent_name.as_str()) || boundary_only.contains(&parent_name.as_str()) {
                    return ActionPlan::Kill; // Downgrade to single kill
                }
            }
        }

        requested_action
    }
}

pub struct MitigationExecutor;

impl MitigationExecutor {
    pub fn execute(plan: ActionPlan, signal: &Signal) {
        match plan {
            ActionPlan::LogOnly => {
                println!("\x1b[33m[POLICY] Mitigation downgraded to LogOnly for PID: {} (Source: {}, Reason: {})\x1b[0m", signal.pid, signal.source, signal.reason);
            }
            ActionPlan::Kill => {
                let reason_str = signal.metadata.as_deref().unwrap_or("Policy Gate Enforced Kill");
                ActiveDefense::engage_kill_switch(signal.pid, reason_str);
            }
            ActionPlan::StorylineKill => {
                let reason_str = signal.metadata.as_deref().unwrap_or("Policy Gate Enforced Storyline Kill");
                ActiveDefense::engage_storyline_kill(signal.pid, reason_str);
            }
            ActionPlan::Contain => {
                ActiveDefense::engage_suspend(signal.pid);
                let process_path = get_process_path(signal.pid);
                ActiveDefense::engage_network_isolation(signal.pid, &process_path);
            }
        }
    }
}