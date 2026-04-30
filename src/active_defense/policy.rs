use std::sync::atomic::Ordering;
use crate::SENTINEL_UI_ACTIVE;
use crate::CURRENT_PROFILE;
use crate::Profile;
use crate::active_defense::ActiveDefense;

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
        if !SENTINEL_UI_ACTIVE.load(Ordering::SeqCst) {
            return ActionPlan::LogOnly;
        }

        // 2. Profile Restrictions
        let profile = crate::CURRENT_PROFILE.lock().unwrap().clone();
        if profile == Profile::Production {
            if signal.source == "IoHunter" || signal.source == "HookHunter" || signal.source == "GhostHunter" {
                return ActionPlan::LogOnly;
            }
        }

        // 3. Protected Process List
        let process_name = crate::kernel_bridge::get_process_name(signal.pid).to_lowercase();
        let protected = [
            "explorer.exe", "svchost.exe", "services.exe", "wininit.exe", 
            "smss.exe", "csrss.exe", "lsass.exe", "winlogon.exe", "cmd.exe", "powershell.exe", "system"
        ];
        
        if protected.contains(&process_name.as_str()) {
            return ActionPlan::LogOnly;
        }

        // Reason 13 Log-only check
        if signal.reason == 13 {
            return ActionPlan::LogOnly;
        }

        // 4. Parent Boundary List (Stop storyline escalation)
        if requested_action == ActionPlan::StorylineKill {
            if let Some(ppid) = crate::kernel_bridge::get_parent_pid(signal.pid) {
                let parent_name = crate::kernel_bridge::get_process_name(ppid).to_lowercase();
                if protected.contains(&parent_name.as_str()) {
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
                let process_path = crate::kernel_bridge::get_process_path(signal.pid);
                ActiveDefense::engage_network_isolation(signal.pid, &process_path);
            }
        }
    }
}