use std::fs;
use std::path::PathBuf;
use chrono::Local;
use indoc::indoc;

pub struct IncidentReport;

impl IncidentReport {
    /// Generates a professional standalone HTML incident report for a terminated threat.
    /// This is a 100% passive, safe, file-writing operation.
    pub fn generate(
        pid: u32,
        process_name: &str,
        reason: &str,
        dump_path: &str,
    ) {
        let timestamp = Local::now();
        let timestamp_str = timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let file_timestamp = timestamp.format("%Y%m%d_%H%M%S").to_string();
        
        let vault_dir = PathBuf::from("C:\\ERDPS_Vault");
        if !vault_dir.exists() {
            let _ = fs::create_dir_all(&vault_dir);
        }
        
        let report_filename = format!("Incident_Report_{}_{}.html", pid, file_timestamp);
        let report_path = vault_dir.join(&report_filename);

        let html_content = format!(indoc! {r#"
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>ERDPS Incident Report - PID {}</title>
                <style>
                    body {{
                        background-color: #121212;
                        color: #e0e0e0;
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        margin: 0;
                        padding: 0;
                    }}
                    .container {{
                        max-width: 900px;
                        margin: 40px auto;
                        background-color: #1e1e1e;
                        border: 1px solid #333;
                        border-radius: 8px;
                        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5);
                        overflow: hidden;
                    }}
                    .header {{
                        background-color: #b71c1c;
                        color: white;
                        padding: 20px;
                        text-align: center;
                        border-bottom: 2px solid #ff5252;
                    }}
                    .header h1 {{
                        margin: 0;
                        font-size: 24px;
                        letter-spacing: 1px;
                        text-transform: uppercase;
                    }}
                    .header p {{
                        margin: 5px 0 0 0;
                        font-size: 14px;
                        opacity: 0.9;
                    }}
                    .content {{
                        padding: 30px;
                    }}
                    .section-title {{
                        color: #ff5252;
                        font-size: 18px;
                        border-bottom: 1px solid #333;
                        padding-bottom: 5px;
                        margin-bottom: 15px;
                        margin-top: 25px;
                        text-transform: uppercase;
                    }}
                    .section-title:first-child {{
                        margin-top: 0;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin-bottom: 20px;
                    }}
                    th, td {{
                        padding: 12px 15px;
                        text-align: left;
                        border-bottom: 1px solid #333;
                    }}
                    th {{
                        background-color: #2a2a2a;
                        color: #aaa;
                        font-weight: normal;
                        width: 30%;
                    }}
                    td {{
                        font-family: 'Consolas', 'Courier New', monospace;
                        color: #4fc3f7;
                    }}
                    .action-taken {{
                        background-color: #2e7d32;
                        color: white;
                        padding: 15px;
                        border-radius: 4px;
                        text-align: center;
                        font-weight: bold;
                        letter-spacing: 1px;
                        margin-top: 30px;
                    }}
                    .footer {{
                        background-color: #1a1a1a;
                        padding: 15px;
                        text-align: center;
                        font-size: 12px;
                        color: #666;
                        border-top: 1px solid #333;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>MALWARE ANALYSIS REPORT</h1>
                        <p>Enterprise Ransomware Defense & Protection System (ERDPS)</p>
                    </div>
                    <div class="content">
                        <div class="section-title">Incident Details</div>
                        <table>
                            <tr>
                                <th>Timestamp</th>
                                <td style="color: #e0e0e0;">{}</td>
                            </tr>
                            <tr>
                                <th>Target Process</th>
                                <td style="color: #ffb74d;">{} (PID: {})</td>
                            </tr>
                            <tr>
                                <th>Detection Reason</th>
                                <td style="color: #ff5252; font-weight: bold;">{}</td>
                            </tr>
                        </table>

                        <div class="section-title">Forensic Artifacts</div>
                        <table>
                            <tr>
                                <th>Memory Dump (Minidump)</th>
                                <td>{}</td>
                            </tr>
                            <tr>
                                <th>System Status</th>
                                <td style="color: #e0e0e0;">Memory dump successfully captured prior to termination for Volatility/WinDbg analysis.</td>
                            </tr>
                        </table>

                        <div class="action-taken">
                            ✓ PROCESS TERMINATED & NETWORK QUARANTINED
                        </div>
                    </div>
                    <div class="footer">
                        Generated automatically by ERDPS Sentinel Agent (Ring-3)
                    </div>
                </div>
            </body>
            </html>
        "#}, pid, timestamp_str, process_name, pid, reason, dump_path);

        if let Err(e) = fs::write(&report_path, html_content) {
            tracing::error!("Failed to write Incident Report to {}: {}", report_path.display(), e);
        } else {
            println!("\x1b[36m[FORENSICS] 📄 Incident Report generated: {}\x1b[0m", report_path.display());
        }
    }
}