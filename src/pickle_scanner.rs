use std::fs::File;
use std::io::Read;
use std::path::Path;

const OPCODE_GLOBAL: u8 = b'c';
const OPCODE_REDUCE: u8 = b'R';

const SUSPICIOUS_MODULES: &[&str] = &[
    "os",
    "system",
    "subprocess",
    "popen",
    "posix",
    "spawn",
    "socket",
    "connect",
    "requests",
    "eval",
    "exec",
    "shutil",
];

pub struct PickleScanner;

impl PickleScanner {
    pub fn scan_file(path: &str) -> Option<String> {
        let path_obj = Path::new(path);
        let ext = path_obj
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !matches!(ext.as_str(), "pkl" | "pickle" | "pt" | "pth" | "bin" | "joblib") {
            return None;
        }

        let mut file = File::open(path).ok()?;
        let mut buffer = Vec::new();
        let _ = file
            .take(1024 * 1024)
            .read_to_end(&mut buffer)
            .ok()?;

        Self::scan_buffer(&buffer)
    }

    fn scan_buffer(data: &[u8]) -> Option<String> {
        let content = String::from_utf8_lossy(data);
        for module in SUSPICIOUS_MODULES {
            if content.contains(module) && Self::verify_opcode_context(data, module.as_bytes()) {
                return Some(format!("Dangerous ML Serialization detected: '{}'", module));
            }
        }
        None
    }

    fn verify_opcode_context(data: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || data.is_empty() {
            return false;
        }

        for i in 0..=data.len().saturating_sub(pattern.len()) {
            if &data[i..i + pattern.len()] == pattern {
                let start = i.saturating_sub(50);
                let context = &data[start..i];
                let has_opcode = context.iter().any(|b| *b == OPCODE_GLOBAL || *b == OPCODE_REDUCE);
                if has_opcode {
                    return true;
                }
            }
        }
        false
    }
}

