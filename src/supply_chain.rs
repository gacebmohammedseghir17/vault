use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read};
use std::path::Path;

pub fn integrity_checks_disabled() -> bool {
    matches!(
        std::env::var("ERDPS_SKIP_MODEL_INTEGRITY").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("True")
    )
}

pub fn sha256_hex(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn verify_file_sha256_allowlist(path: &Path, allowlist: &[&str]) -> Result<bool, std::io::Error> {
    let actual = sha256_hex(path)?;
    Ok(allowlist.iter().any(|h| h.eq_ignore_ascii_case(&actual)))
}

pub fn calculate_sha256(path: &Path) -> Result<String, std::io::Error> {
    sha256_hex(path)
}

pub fn verify_model_integrity(path: &Path, allowlist: &[&str]) -> Result<bool, std::io::Error> {
    verify_file_sha256_allowlist(path, allowlist)
}
