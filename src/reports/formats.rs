//! Export Format Implementations
//!
//! This module contains the specific implementations for exporting reports
//! to different formats: PDF, CSV, JSON, and XML.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
// use chrono::Utc; // Will be used when implementing timestamp formatting
use csv::Writer;
use printpdf::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer as XmlWriter;
use serde_json;
use tokio::fs;

use super::ReportData;

/// Trait for export format implementations
#[async_trait::async_trait]
pub trait FormatExporter {
    async fn export(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf>;
}

/// PDF export implementation
pub struct PdfExporter;

impl PdfExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl FormatExporter for PdfExporter {
    async fn export(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        let (doc, page1, layer1) =
            PdfDocument::new("ERDPS Report Export", Mm(210.0), Mm(297.0), "Layer 1");
        let current_layer = doc.get_page(page1).get_layer(layer1);

        // Load fonts
        let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
        let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;

        let mut y_position = Mm(270.0);
        let line_height = Mm(6.0);

        // Title
        current_layer.use_text(
            "ERDPS Security Report Export",
            16.0,
            Mm(20.0),
            y_position,
            &font_bold,
        );
        y_position -= line_height * 2.0;

        // Export timestamp
        let export_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        current_layer.use_text(
            format!("Generated: {}", export_time),
            10.0,
            Mm(20.0),
            y_position,
            &font_regular,
        );
        y_position -= line_height * 2.0;

        // Report summary
        current_layer.use_text(
            format!("Total Reports: {}", reports.len()),
            12.0,
            Mm(20.0),
            y_position,
            &font_bold,
        );
        y_position -= line_height * 2.0;

        // Individual reports
        for (index, report) in reports.iter().enumerate() {
            if y_position < Mm(30.0) {
                // Add new page if needed
                let (new_page, new_layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
                let _current_layer = doc.get_page(new_page).get_layer(new_layer);
                y_position = Mm(270.0);
            }

            // Report header
            current_layer.use_text(
                format!("Report #{}: {}", index + 1, report.id),
                12.0,
                Mm(20.0),
                y_position,
                &font_bold,
            );
            y_position -= line_height;

            // Report details
            current_layer.use_text(
                format!("Type: {}", report.report_type),
                10.0,
                Mm(25.0),
                y_position,
                &font_regular,
            );
            y_position -= line_height;

            current_layer.use_text(
                format!(
                    "Timestamp: {}",
                    report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                ),
                10.0,
                Mm(25.0),
                y_position,
                &font_regular,
            );
            y_position -= line_height;

            // Report data summary
            if let Some(scan_results) = report.data.get("scan_results") {
                if let Some(threats) = scan_results.get("threats_detected") {
                    current_layer.use_text(
                        format!("Threats Detected: {}", threats),
                        10.0,
                        Mm(25.0),
                        y_position,
                        &font_regular,
                    );
                    y_position -= line_height;
                }

                if let Some(files) = scan_results.get("files_scanned") {
                    current_layer.use_text(
                        format!("Files Scanned: {}", files),
                        10.0,
                        Mm(25.0),
                        y_position,
                        &font_regular,
                    );
                    y_position -= line_height;
                }
            }

            y_position -= line_height; // Extra spacing between reports
        }

        // Save PDF
        let file = File::create(output_path).context("Failed to create PDF file")?;
        let mut buf_writer = BufWriter::new(file);
        doc.save(&mut buf_writer).context("Failed to save PDF")?;

        Ok(output_path.to_path_buf())
    }
}

/// CSV export implementation
pub struct CsvExporter;

impl CsvExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl FormatExporter for CsvExporter {
    async fn export(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        let file = File::create(output_path).context("Failed to create CSV file")?;
        let mut writer = Writer::from_writer(file);

        // Write header
        writer.write_record(&[
            "Report ID",
            "Type",
            "Timestamp",
            "Threats Detected",
            "Files Scanned",
            "Scan Duration",
            "Agent ID",
            "Version",
        ])?;

        // Write data rows
        for report in reports {
            let threats_detected = report
                .data
                .get("scan_results")
                .and_then(|sr| sr.get("threats_detected"))
                .and_then(|td| td.as_u64())
                .unwrap_or(0)
                .to_string();

            let files_scanned = report
                .data
                .get("scan_results")
                .and_then(|sr| sr.get("files_scanned"))
                .and_then(|fs| fs.as_u64())
                .unwrap_or(0)
                .to_string();

            let scan_duration = report
                .data
                .get("scan_results")
                .and_then(|sr| sr.get("scan_duration"))
                .and_then(|sd| sd.as_str())
                .unwrap_or("N/A")
                .to_string();

            let agent_id = report
                .metadata
                .get("agent_id")
                .unwrap_or(&"N/A".to_string())
                .clone();

            let version = report
                .metadata
                .get("version")
                .unwrap_or(&"N/A".to_string())
                .clone();

            writer.write_record(&[
                &report.id,
                &report.report_type,
                &report.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                &threats_detected,
                &files_scanned,
                &scan_duration,
                &agent_id,
                &version,
            ])?;
        }

        writer.flush()?;
        Ok(output_path.to_path_buf())
    }
}

/// JSON export implementation
pub struct JsonExporter;

impl JsonExporter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl FormatExporter for JsonExporter {
    async fn export(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        let export_data = serde_json::json!({
            "export_metadata": {
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "total_reports": reports.len(),
                "export_version": "1.0",
                "system": "ERDPS"
            },
            "reports": reports
        });

        let json_string = serde_json::to_string_pretty(&export_data)
            .context("Failed to serialize reports to JSON")?;

        fs::write(output_path, json_string)
            .await
            .context("Failed to write JSON file")?;

        Ok(output_path.to_path_buf())
    }
}

/// XML export implementation
pub struct XmlExporter;

impl XmlExporter {
    pub fn new() -> Self {
        XmlExporter
    }
}

#[async_trait::async_trait]
impl FormatExporter for XmlExporter {
    async fn export(&self, reports: &[ReportData], output_path: &Path) -> Result<PathBuf> {
        let file = File::create(output_path).context("Failed to create XML file")?;
        let mut writer = XmlWriter::new(BufWriter::new(file));

        // XML declaration
        writer.write_event(Event::Decl(quick_xml::events::BytesDecl::new(
            "1.0",
            Some("UTF-8"),
            None,
        )))?;

        // Root element
        let mut root = BytesStart::new("erdps_export");
        root.push_attribute(("generated_at", chrono::Utc::now().to_rfc3339().as_str()));
        root.push_attribute(("total_reports", reports.len().to_string().as_str()));
        root.push_attribute(("version", "1.0"));
        writer.write_event(Event::Start(root))?;

        // Export metadata
        writer.write_event(Event::Start(BytesStart::new("metadata")))?;

        writer.write_event(Event::Start(BytesStart::new("system")))?;
        // writer.write_event(Event::Text(BytesText::new("ERDPS")))?;
        // writer.write_event(Event::End(BytesEnd::new("system")))?;

        writer.write_event(Event::Start(BytesStart::new("export_version")))?;
        writer.write_event(Event::Text(BytesText::new("1.0")))?;
        writer.write_event(Event::End(BytesEnd::new("export_version")))?;

        writer.write_event(Event::End(BytesEnd::new("metadata")))?;

        // Reports
        writer.write_event(Event::Start(BytesStart::new("reports")))?;

        for report in reports {
            let mut report_elem = BytesStart::new("report");
            report_elem.push_attribute(("id", report.id.as_str()));
            report_elem.push_attribute(("type", report.report_type.as_str()));
            writer.write_event(Event::Start(report_elem))?;

            // Timestamp
            writer.write_event(Event::Start(BytesStart::new("timestamp")))?;
            writer.write_event(Event::Text(BytesText::new(
                &report.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            )))?;
            writer.write_event(Event::End(BytesEnd::new("timestamp")))?;

            // Data
            writer.write_event(Event::Start(BytesStart::new("data")))?;
            if let Some(scan_results) = report.data.get("scan_results") {
                writer.write_event(Event::Start(BytesStart::new("scan_results")))?;

                if let Some(threats) = scan_results.get("threats_detected") {
                    writer.write_event(Event::Start(BytesStart::new("threats_detected")))?;
                    writer.write_event(Event::Text(BytesText::new(&threats.to_string())))?;
                    writer.write_event(Event::End(BytesEnd::new("threats_detected")))?;
                }

                if let Some(files) = scan_results.get("files_scanned") {
                    writer.write_event(Event::Start(BytesStart::new("files_scanned")))?;
                    writer.write_event(Event::Text(BytesText::new(&files.to_string())))?;
                    writer.write_event(Event::End(BytesEnd::new("files_scanned")))?;
                }

                if let Some(duration) = scan_results.get("scan_duration") {
                    writer.write_event(Event::Start(BytesStart::new("scan_duration")))?;
                    writer.write_event(Event::Text(BytesText::new(
                        duration.as_str().unwrap_or("N/A"),
                    )))?;
                    writer.write_event(Event::End(BytesEnd::new("scan_duration")))?;
                }

                writer.write_event(Event::End(BytesEnd::new("scan_results")))?;
            }
            writer.write_event(Event::End(BytesEnd::new("data")))?;

            // Metadata
            writer.write_event(Event::Start(BytesStart::new("metadata")))?;
            for (key, value) in &report.metadata {
                writer.write_event(Event::Start(BytesStart::new(key)))?;
                writer.write_event(Event::Text(BytesText::new(value)))?;
                writer.write_event(Event::End(BytesEnd::new(key)))?;
            }
            writer.write_event(Event::End(BytesEnd::new("metadata")))?;

            writer.write_event(Event::End(BytesEnd::new("report")))?;
        }

        writer.write_event(Event::End(BytesEnd::new("reports")))?;
        writer.write_event(Event::End(BytesEnd::new("erdps_export")))?;

        Ok(output_path.to_path_buf())
    }
}
