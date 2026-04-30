# Summary
Make ERDPS stable, deterministic, and performant by enforcing strict mitigation policies, resolving UI-related panics, and implementing distinct execution profiles. Mitigation actions are restricted strictly to Sentinel mode and routed through a single centralized Policy Gate and Executor.

# Current State Analysis
- Kills are being executed directly via `ActiveDefense::engage_kill_switch` and `engage_storyline_kill` across multiple scattered modules (`kernel_bridge.rs`, `io_hunter.rs`, `canary_sentinel.rs`, `behavior.rs`, etc.).
- Modules are issuing mitigation commands even when `SENTINEL_UI_ACTIVE` is false, leading to unwanted behavior in Forensic or Menu modes.
- `src/main.rs` uses `.unwrap()` on `read_line` calls, which panics and crashes the agent if standard input fails or is piped unexpectedly.
- Kernel Reason 13 (Cross-Process Thread Injection) is noisy and causing false positive kills.
- Immortality (`RtlSetProcessIsCritical`) is unconditionally enabled, creating BSOD risks during normal testing/development.
- High-frequency polling (e.g., 10ms in `behavior.rs`) and heavy background hunters (`hook_hunter`, `ghost_hunter`) are always running, causing high CPU usage ("lag") in VM environments.

# Proposed Changes

## Phase 1: Stability Hotfix (stop chaos immediately)
1. **Prevent Kills Outside Sentinel Mode**
   - **Files:** `src/kernel_bridge.rs`, `src/canary_sentinel.rs`, `src/io_hunter.rs`, `src/behavior.rs`, `src/hook_hunter.rs`, `src/ghost_hunter.rs`
   - **What/How:** Add logic to check `crate::SENTINEL_UI_ACTIVE.load(Ordering::SeqCst)`. If false, block any calls to kill/suspend/quarantine/rollback/snapshot, allowing only logging.
2. **Remove Self-Exit Panic Paths**
   - **Files:** `src/main.rs`, `src/forensic_shell.rs`
   - **What/How:** Replace `io::stdin().read_line(&mut input).unwrap();` with safe fallback handling (`if io::stdin().read_line(&mut input).is_err() { break; }`) so the agent never exits unexpectedly if stdin fails.
3. **Disable Auto-Kill on Noisy Kernel Reason 13**
   - **Files:** `src/kernel_bridge.rs`
   - **What/How:** Change the action for kernel reason 13 to log-only (e.g., print a `[WARNING]` instead of `[CRITICAL]` and remove the `ActiveDefense::engage_storyline_kill` call).
4. **Disable Immortality by Default**
   - **Files:** `src/main.rs`, `src/active_defense/mod.rs`
   - **What/How:** In `src/active_defense/mod.rs` inside `harden_agent_process()`, wrap the logic with `if std::env::var("ERDPS_IMMORTALITY").unwrap_or("0".into()) != "1" { return; }`.

## Phase 2: Mitigation Policy Gate (single decision + single executor)
1. **Create Policy Gate & Executor**
   - **Files:** Create `src/active_defense/policy.rs` (and export in `mod.rs`).
   - **What/How:**
     - Define `Signal` struct (source, pid, reason, file_path, metadata).
     - Define `ActionPlan` enum (`LogOnly`, `Contain`, `Kill`, `StorylineKill`).
     - Implement `PolicyGate::decide(signal: &Signal, requested_action: ActionPlan) -> ActionPlan`. This function will enforce mode restrictions (`SENTINEL_UI_ACTIVE`), the protected process list, and parent boundary list.
     - Implement `MitigationExecutor::execute(plan: ActionPlan, signal: &Signal)` to handle the actual routing to `ActiveDefense::engage_kill_switch`, `engage_storyline_kill`, quarantine, and rollback actions.
2. **Route All Mitigation Through Executor**
   - **Files:** `src/kernel_bridge.rs`, `src/io_hunter.rs`, `src/canary_sentinel.rs`, `src/behavior.rs`, `src/ai_copilot/forensics.rs`, `src/rootkit_hunter.rs`, `src/hook_hunter.rs`, `src/ghost_hunter.rs`
   - **What/How:** Replace all direct calls to `ActiveDefense::engage_storyline_kill` and `ActiveDefense::engage_kill_switch` with `MitigationExecutor::execute(PolicyGate::decide(...))`.

## Phase 3: Profiles (Production vs Lab) to fix lag
1. **Add Configuration/Profile**
   - **Files:** `src/main.rs`
   - **What/How:** Add an enum `Profile { Production, Lab, Adaptive }` and a static global `CURRENT_PROFILE`. Initialize it from the `ERDPS_PROFILE` environment variable (default to `Production`).
2. **Apply Production Defaults**
   - **Files:** `src/main.rs`
   - **What/How:** Wrap the spawning of `GhostHunter` and `HookHunter` with `if *CURRENT_PROFILE.lock() != Profile::Production`.
   - **Files:** `src/behavior.rs`
   - **What/How:** Change the polling sleep interval: `100ms` for `Production`, `10ms` for `Lab`.
   - **Files:** `src/active_defense/policy.rs` (Policy Gate)
   - **What/How:** Ensure `IoHunter` kill requests are downgraded to `LogOnly` based on PID guessing from notify when the profile is `Production`. Telemetry only unless correlated by kernel events.

# Assumptions & Decisions
- **No Refactoring Unrelated Code:** Changes will strictly focus on stability and mitigation centralization. Existing logic (e.g., how AI models load) remains untouched.
- **Centralized Telemetry:** When `PolicyGate` downgrades an action to `LogOnly`, it will still emit a log/alert (so the behavior is observed) but will not execute any disruptive system calls.
- **Protected Process List:** Standard Windows binaries (`explorer.exe`, `svchost.exe`, `system`, etc.) will be embedded directly in the `PolicyGate` to prevent system bricking.

# Verification Steps
- **Phase 1 Acceptance:** Run agent in Menu mode; simulate alerts, verify no kills occur. Enter Sentinel mode, leave idle for 2 minutes; ensure no self-exit/panic.
- **Phase 2 Acceptance:** Search codebase (`grep`) for `ActiveDefense::engage_kill_switch` and `engage_storyline_kill`. Verify they are only called from `policy.rs` (and possibly `active_defense/mod.rs` itself).
- **Phase 3 Acceptance:** Run in default (Production) mode and monitor CPU usage to ensure VM lag is resolved. Set `ERDPS_PROFILE=lab` and verify aggressive heuristics are active.