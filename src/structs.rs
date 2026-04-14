use serde::{Serialize, Deserialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use chrono::Utc;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanReport {
    pub id: String,
    pub timestamp: String,
    pub host_info: HostMetadata,
    pub scan_target: TargetInfo,
    pub verdict: String,
    pub risk_score: u8,
    pub modules: ModuleResults,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostMetadata {
    pub hostname: String,
    pub os: String,
    pub user: String,
    pub arch: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TargetInfo {
    pub path: String,
    pub size: u64,
    pub hash_sha256: String,
    pub imphash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModuleResults {
    pub yara: Vec<String>,
    pub ml: f32,
    pub entropy: f32,
    pub integrity: bool,
    pub network: Vec<String>,
    pub cloud_intel_match: bool,
    pub pe_writable_section: bool,
    pub pe_injection_imports: bool,
    pub pe_crypto_imports: bool,
    pub pe_heuristics: bool,
    pub mitre_tactics: Vec<String>,
}

impl ScanReport {
    pub fn new(target: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            host_info: HostMetadata {
                hostname: whoami::hostname(),
                os: format!("{} {}", whoami::platform(), whoami::distro()),
                user: whoami::username(),
                arch: std::env::consts::ARCH.to_string(),
            },
            scan_target: TargetInfo {
                path: target.to_string(),
                size: 0,
                hash_sha256: "Pending".to_string(),
                imphash: "Pending".to_string(),
            },
            verdict: "PENDING".to_string(),
            risk_score: 0,
            modules: ModuleResults {
                yara: Vec::new(),
                ml: 0.0,
                entropy: 0.0,
                integrity: true,
                network: Vec::new(),
                cloud_intel_match: false,
                pe_writable_section: false,
                pe_injection_imports: false,
                pe_crypto_imports: false,
                pe_heuristics: false,
                mitre_tactics: Vec::new(),
            },
        }
    }

    pub fn save_json(&self) -> Result<String, std::io::Error> {
        let reports_dir = Path::new("reports");
        if !reports_dir.exists() { fs::create_dir(reports_dir)?; }

        let safe_verdict = self.verdict.replace(" ", "_").to_uppercase();
        let safe_timestamp = self.timestamp.replace(":", "-").replace(".", "_");
        
        let filename = format!("report_{}_{}.json", safe_timestamp, safe_verdict);
        let file_path = reports_dir.join(&filename);

        let json = serde_json::to_string_pretty(&self)?;
        let mut file = File::create(&file_path)?;
        file.write_all(json.as_bytes())?;

        Ok(file_path.to_string_lossy().to_string())
    }

    pub fn save_html(&self) -> Result<String, std::io::Error> {
        let reports_dir = Path::new("reports");
        if !reports_dir.exists() { fs::create_dir(reports_dir)?; }

        let safe_verdict = self.verdict.replace(" ", "_").to_uppercase();
        let safe_timestamp = self.timestamp.replace(":", "-").replace(".", "_");
        let filename = format!("report_{}_{}.html", safe_timestamp, safe_verdict);
        let file_path = reports_dir.join(&filename);

        // --- HTML GENERATION ---
        let color_class = match self.verdict.as_str() {
            "MALICIOUS" => "danger",
            "SUSPICIOUS" => "warning",
            _ => "safe",
        };

        // Build Lists
        let yara_list: String = self.modules.yara.iter()
            .map(|r| format!("<li><span class='badge danger'>MATCH</span> {}</li>", r))
            .collect::<Vec<String>>().join("");
        
        let yara_display = if yara_list.is_empty() {
            "<li><span class='badge safe'>NONE</span> No Threat Signatures Detected</li>".to_string()
        } else { yara_list };

        let cloud_display = if self.modules.cloud_intel_match {
            "<tr><td class='label'>Cloud Intel</td><td class='val danger'>[MATCH] Simulated Global Threat Database Match! (68/72 Vendors flagged as MALICIOUS)</td></tr>".to_string()
        } else {
            "<tr><td class='label'>Cloud Intel</td><td class='val safe'>CLEAN - Not Found in Database</td></tr>".to_string()
        };

        let mut pe_details = Vec::new();
        if self.modules.pe_writable_section {
            pe_details.push("<span class='badge danger'>ANOMALY</span> Executable section is WRITABLE (Packed/Obfuscated)");
        }
        if self.modules.pe_injection_imports {
            pe_details.push("<span class='badge danger'>IAT ANOMALY</span> Injection Signature Detected (VirtualAllocEx / CreateRemoteThread)");
        }
        if self.modules.pe_crypto_imports {
            pe_details.push("<span class='badge danger'>IAT ANOMALY</span> Crypto Signature Detected (CryptEncrypt)");
        }
        if self.modules.pe_heuristics {
            pe_details.push("<span class='badge warning'>HEURISTICS</span> Static Signature Match Found!");
        }
        let pe_display = if pe_details.is_empty() {
            "<tr><td class='label'>PE Analysis</td><td class='val safe'>CLEAN - No Anomalies Detected</td></tr>".to_string()
        } else {
            format!("<tr><td class='label'>PE Analysis</td><td class='val'>{}</td></tr>", pe_details.join("<br>"))
        };

        let mitre_display = if self.modules.mitre_tactics.is_empty() {
            "".to_string()
        } else {
            let items = self.modules.mitre_tactics.iter()
                .map(|t| format!("<li><span class='badge danger'>TACTIC</span> {}</li>", t))
                .collect::<Vec<_>>().join("");
            format!("<div class=\"section\"><h2>MITRE ATT&CK MAPPING</h2><ul>{}</ul></div>", items)
        };

        let html = HTML_TEMPLATE
            .replace("{{ID}}", &self.id)
            .replace("{{TIMESTAMP}}", &self.timestamp)
            .replace("{{VERDICT}}", &self.verdict)
            .replace("{{COLOR_CLASS}}", color_class)
            .replace("{{SCORE}}", &self.risk_score.to_string())
            .replace("{{FILE_PATH}}", &self.scan_target.path)
            .replace("{{FILE_SIZE}}", &self.scan_target.size.to_string())
            .replace("{{SHA256}}", &self.scan_target.hash_sha256)
            .replace("{{IMPHASH}}", &self.scan_target.imphash)
            .replace("{{ENTROPY}}", &format!("{:.4}", self.modules.entropy))
            .replace("{{ML_SCORE}}", &format!("{:.4}", self.modules.ml))
            .replace("{{CLOUD_DISPLAY}}", &cloud_display)
            .replace("{{PE_DISPLAY}}", &pe_display)
            .replace("{{MITRE_DISPLAY}}", &mitre_display)
            .replace("{{YARA_LIST}}", &yara_display);

        let mut file = File::create(&file_path)?;
        file.write_all(html.as_bytes())?;

        Ok(file_path.to_string_lossy().to_string())
    }
}

// --- EMBEDDED TEMPLATE (God Mode UI) ---
const HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>ERDPS Forensic Report</title>
    <style>
        body { background-color: #0f172a; color: #e2e8f0; font-family: 'Courier New', monospace; margin: 0; padding: 40px; }
        .container { max_width: 900px; margin: 0 auto; border: 1px solid #334155; padding: 20px; background: #1e293b; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        .header { display: flex; justify-content: space-between; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 20px; }
        h1 { margin: 0; font-size: 24px; color: #38bdf8; }
        .verdict { font-size: 32px; font-weight: bold; padding: 10px 20px; border-radius: 4px; text-align: center; margin-bottom: 20px; }
        .danger { color: #ef4444; border: 2px solid #ef4444; background: rgba(239, 68, 68, 0.1); }
        .warning { color: #f59e0b; border: 2px solid #f59e0b; background: rgba(245, 158, 11, 0.1); }
        .safe { color: #22c55e; border: 2px solid #22c55e; background: rgba(34, 197, 94, 0.1); }
        .section { margin-bottom: 30px; }
        .section h2 { color: #94a3b8; border-bottom: 1px solid #475569; padding-bottom: 5px; font-size: 16px; text-transform: uppercase; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        td { padding: 8px; border-bottom: 1px solid #334155; }
        .label { width: 150px; color: #64748b; font-weight: bold; }
        .val { color: #f8fafc; word-break: break-all; }
        ul { list-style: none; padding: 0; }
        li { padding: 5px 0; border-bottom: 1px solid #334155; }
        .badge { font-size: 10px; padding: 2px 6px; border-radius: 2px; margin-right: 10px; font-weight: bold; }
        .footer { font-size: 10px; color: #475569; text-align: center; margin-top: 40px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>ERDPS SENTINEL</h1>
                <div style="font-size: 12px; color: #64748b;">Automated Forensic Report</div>
            </div>
            <div style="text-align: right;">
                <div>ID: {{ID}}</div>
                <div>{{TIMESTAMP}}</div>
            </div>
        </div>

        <div class="verdict {{COLOR_CLASS}}">
            VERDICT: {{VERDICT}} (RISK: {{SCORE}}/100)
        </div>

        <div class="section">
            <h2>Target Intelligence</h2>
            <table>
                <tr><td class="label">File Path</td><td class="val">{{FILE_PATH}}</td></tr>
                <tr><td class="label">Size</td><td class="val">{{FILE_SIZE}} bytes</td></tr>
                <tr><td class="label">SHA256</td><td class="val">{{SHA256}}</td></tr>
                <tr><td class="label">ImpHash</td><td class="val">{{IMPHASH}}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Detection Engines</h2>
            <table>
                <tr><td class="label">Entropy</td><td class="val">{{ENTROPY}} (High > 7.2)</td></tr>
                <tr><td class="label">Neural AI</td><td class="val">{{ML_SCORE}} (Probability)</td></tr>
                {{CLOUD_DISPLAY}}
                {{PE_DISPLAY}}
            </table>
        </div>

        <div class="section">
            <h2>YARA Signatures</h2>
            <ul>
                {{YARA_LIST}}
            </ul>
        </div>

        {{MITRE_DISPLAY}}

        <div class="footer">
            GENERATED BY ERDPS-AGENT | GOD MODE ACTIVE | UNCLASSIFIED
        </div>
    </div>
</body>
</html>
"#;
