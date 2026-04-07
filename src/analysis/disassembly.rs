use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use goblin::Object;
#[cfg(feature = "advanced-disassembly")]
use capstone::prelude::*;
// capstone disabled in this environment

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DisassemblyFinding {
    pub kind: String,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DisassemblyReport {
    pub path: String,
    pub file_type: String,
    pub architecture: String,
    pub imports: Vec<String>,
    pub strings: Vec<String>,
    pub suspicious: Vec<DisassemblyFinding>,
    pub instructions_sample: Vec<String>,
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf8(cur.clone()) { out.push(s); }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len { if let Ok(s) = String::from_utf8(cur) { out.push(s); } }
    out
}

pub fn analyze_file(path: PathBuf) -> Result<DisassemblyReport, String> {
    let data = std::fs::read(&path).map_err(|e| e.to_string())?;
    let imports = Vec::new();
    let mut strings = extract_ascii_strings(&data, 6);
    let mut utf16s = extract_utf16_strings(&data, 6);
    strings.extend(utf16s.drain(..));
    strings.truncate(500);
    let mut suspicious = Vec::new();
    let mut instructions_sample = Vec::new();
    let file_type: String;
    #[cfg(feature = "advanced-disassembly")]
    let mut architecture = String::from("unknown");
    #[cfg(not(feature = "advanced-disassembly"))]
    let architecture = String::from("unknown");

    match Object::parse(&data) {
        Ok(Object::PE(pe)) => {
            file_type = String::from("pe");
            #[cfg(feature = "advanced-disassembly")]
            {
                let machine = pe.header.coff_header.machine;
                match machine {
                    0x8664 => { architecture = String::from("x86_64"); }
                    0x14c => { architecture = String::from("x86"); }
                    0x1c0 => { architecture = String::from("arm"); }
                    0xaa64 => { architecture = String::from("arm64"); }
                    _ => {}
                }
            }
            for s in pe.sections.iter() {
                let name = s.name().unwrap_or("").to_string();
                if name.trim() == ".text" {
                    let ptr = s.pointer_to_raw_data as usize;
                    let sz = s.size_of_raw_data as usize;
                    if ptr < data.len() {
                        let end = std::cmp::min(data.len(), ptr + sz);
                        let slice = &data[ptr..end];
                        #[cfg(feature = "advanced-disassembly")]
                        {
                            let eng = match architecture.as_str() {
                                "x86_64" => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build(),
                                "x86" => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build(),
                                "arm64" => Capstone::new().arm64().build(),
                                "arm" => Capstone::new().arm().build(),
                                _ => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build(),
                            };
                            if let Ok(cs) = eng {
                                if let Ok(insns) = cs.disasm_all(slice, 0) {
                                    for i in insns.iter().take(32) {
                                        let m = i.mnemonic().unwrap_or("");
                                        let o = i.op_str().unwrap_or("");
                                        instructions_sample.push(format!("{} {}", m, o));
                                    }
                                }
                            }
                        }
                        #[cfg(not(feature = "advanced-disassembly"))]
                        {
                            let take = std::cmp::min(slice.len(), 64);
                            let mut hex = String::new();
                            for b in &slice[..take] { hex.push_str(&format!("{:02x}", b)); }
                            instructions_sample.push(hex);
                        }
                    }
                }
            }
        }
        Ok(_) => {
            file_type = String::from("other");
        }
        Err(_) => {
            file_type = String::from("raw");
        }
    }

    let suspicious_apis = [
        "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "RegSetValue", "RegCreateKey",
        "SHADOWCOPY", "vssadmin", "CryptEncrypt", "CryptAcquireContext", "DeleteFile", "MoveFile",
    ];
    for api in suspicious_apis.iter() {
        if strings.iter().any(|s| s.to_lowercase().contains(&api.to_lowercase())) {
            suspicious.push(DisassemblyFinding{ kind: String::from("api"), detail: api.to_string() });
        }
    }
    for s in strings.iter() {
        let sl = s.to_lowercase();
        if sl.contains("vssadmin delete shadows") || sl.contains("shadow copies") { suspicious.push(DisassemblyFinding{ kind: String::from("shadow_copy_deletion"), detail: s.clone() }); }
        if sl.contains(".onion") || sl.contains("bitcoin") || sl.contains("ransom") { suspicious.push(DisassemblyFinding{ kind: String::from("ransom_indicator"), detail: s.clone() }); }
        if sl.contains("import os") || sl.contains("subprocess") || sl.contains("sys.argv") || sl.contains("base64.b64decode") { suspicious.push(DisassemblyFinding{ kind: String::from("python_indicator"), detail: s.clone() }); }
        if sl.contains("invoke-expression") || sl.contains("iex ") || sl.contains("frombase64string") || sl.contains("new-object") || sl.contains("downloadstring") || sl.contains("start-process") { suspicious.push(DisassemblyFinding{ kind: String::from("powershell_indicator"), detail: s.clone() }); }
        if looks_like_base64(&sl) { suspicious.push(DisassemblyFinding{ kind: String::from("base64_indicator"), detail: s.clone() }); }
    }

    Ok(DisassemblyReport{
        path: path.display().to_string(),
        file_type,
        architecture,
        imports,
        strings: strings.into_iter().take(100).collect(),
        suspicious,
        instructions_sample,
    })
}
fn extract_utf16_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let mut buf = Vec::new();
        let mut j = i;
        while j + 1 < data.len() {
            let c = u16::from_le_bytes([data[j], data[j + 1]]);
            if c >= 32 && c < 127 { buf.push(c as u8); j += 2; } else { break; }
        }
        if buf.len() >= min_len { if let Ok(s) = String::from_utf8(buf) { out.push(s); } }
        i = j + 2;
    }
    out
}
fn looks_like_base64(s: &str) -> bool {
    let len = s.len();
    if len < 16 { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}