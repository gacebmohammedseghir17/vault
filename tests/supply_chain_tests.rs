use std::io::Write;

use erdps_agent::graph_engine::TopologyEngine;
use erdps_agent::supply_chain;

#[test]
fn verify_file_sha256_allowlist_accepts_expected_hash() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"hello").unwrap();

    let actual = supply_chain::sha256_hex(f.path()).unwrap();
    let allow = vec![actual.as_str()];

    assert!(supply_chain::verify_file_sha256_allowlist(f.path(), &allow).unwrap());
}

#[test]
fn verify_file_sha256_allowlist_rejects_mismatch() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(b"hello").unwrap();

    let bad = "00".repeat(32);
    let allow = vec![bad.as_str()];
    assert!(!supply_chain::verify_file_sha256_allowlist(f.path(), &allow).unwrap());
}

#[test]
fn topology_engine_flags_office_spawning_shell() {
    let mut topo = TopologyEngine::new();
    let alert = topo.track_process_spawn(100, "WINWORD.EXE".to_string(), 200, "powershell.exe".to_string());
    assert!(alert.is_some());
}

