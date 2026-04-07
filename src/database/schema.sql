-- Production Database Schema for Ransolution Security Engine
-- Based on production_architecture_specification.md

-- Detection Scan Table
CREATE TABLE detection_scans (
    scan_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('BEHAVIORAL', 'MEMORY', 'NETWORK', 'YARA', 'COMPREHENSIVE')),
    status TEXT NOT NULL CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMEOUT')),
    priority TEXT DEFAULT 'MEDIUM' CHECK (priority IN ('HIGH', 'MEDIUM', 'LOW')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    duration_ms INTEGER,
    cpu_usage_percent REAL,
    memory_usage_mb INTEGER,
    files_scanned INTEGER DEFAULT 0
);

CREATE INDEX idx_detection_scans_status ON detection_scans(status);
CREATE INDEX idx_detection_scans_created_at ON detection_scans(created_at DESC);
CREATE INDEX idx_detection_scans_scan_type ON detection_scans(scan_type);

-- Threat Families Table
CREATE TABLE threat_families (
    family_id TEXT PRIMARY KEY,
    family_name TEXT NOT NULL,
    description TEXT NOT NULL,
    mitigation_strategies TEXT -- JSON
);

-- Detection Result Table
CREATE TABLE detection_results (
    result_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    threat_family_id TEXT NOT NULL,
    confidence_score REAL NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    detection_engine TEXT NOT NULL,
    indicators TEXT NOT NULL, -- JSON array
    recommended_actions TEXT NOT NULL, -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES detection_scans(scan_id),
    FOREIGN KEY (threat_family_id) REFERENCES threat_families(family_id)
);

CREATE INDEX idx_detection_results_scan_id ON detection_results(scan_id);
CREATE INDEX idx_detection_results_confidence ON detection_results(confidence_score DESC);
CREATE INDEX idx_detection_results_engine ON detection_results(detection_engine);

-- Malware Sample Table
CREATE TABLE malware_samples (
    sample_id TEXT PRIMARY KEY,
    sha256_hash TEXT UNIQUE NOT NULL,
    family_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    threat_level TEXT NOT NULL CHECK (threat_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    validation_status TEXT DEFAULT 'PENDING' CHECK (validation_status IN ('PENDING', 'VALIDATED', 'FAILED')),
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_validated DATETIME
);

CREATE INDEX idx_malware_samples_hash ON malware_samples(sha256_hash);
CREATE INDEX idx_malware_samples_family ON malware_samples(family_name);
CREATE INDEX idx_malware_samples_threat_level ON malware_samples(threat_level);

-- Validation Run Table
CREATE TABLE validation_runs (
    validation_id TEXT PRIMARY KEY,
    sample_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    mttd_seconds REAL,
    accuracy_score REAL CHECK (accuracy_score >= 0.0 AND accuracy_score <= 1.0),
    detected BOOLEAN NOT NULL,
    false_positive BOOLEAN DEFAULT FALSE,
    run_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    isolation_config TEXT, -- JSON
    FOREIGN KEY (sample_id) REFERENCES malware_samples(sample_id),
    FOREIGN KEY (scan_id) REFERENCES detection_scans(scan_id)
);

CREATE INDEX idx_validation_runs_sample_id ON validation_runs(sample_id);
CREATE INDEX idx_validation_runs_detected ON validation_runs(detected);
CREATE INDEX idx_validation_runs_mttd ON validation_runs(mttd_seconds);

-- Rule Families Table
CREATE TABLE rule_families (
    family_id TEXT PRIMARY KEY,
    family_name TEXT NOT NULL,
    description TEXT NOT NULL,
    provenance TEXT NOT NULL
);

-- YARA Rule Table
CREATE TABLE yara_rules (
    rule_id TEXT PRIMARY KEY,
    rule_name TEXT UNIQUE NOT NULL,
    family_id TEXT NOT NULL,
    rule_content TEXT NOT NULL,
    version TEXT NOT NULL,
    compiled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    enabled BOOLEAN DEFAULT TRUE,
    performance_score REAL,
    accuracy_score REAL,
    FOREIGN KEY (family_id) REFERENCES rule_families(family_id)
);

CREATE INDEX idx_yara_rules_family ON yara_rules(family_id);
CREATE INDEX idx_yara_rules_enabled ON yara_rules(enabled);
CREATE INDEX idx_yara_rules_performance ON yara_rules(performance_score DESC);

-- GitHub Sources Table for YARA rule downloads
CREATE TABLE github_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    repository TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT 'main',
    rules_path TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT 1,
    update_frequency_hours INTEGER NOT NULL DEFAULT 24,
    last_update INTEGER -- Unix timestamp
);

CREATE INDEX idx_github_sources_active ON github_sources(is_active);
CREATE INDEX idx_github_sources_name ON github_sources(name);

-- System Metrics Table
CREATE TABLE system_metrics (
    metric_id TEXT PRIMARY KEY,
    cpu_usage_percent REAL NOT NULL,
    memory_usage_mb INTEGER NOT NULL,
    disk_io_mbps REAL NOT NULL,
    network_io_mbps REAL NOT NULL,
    active_scans INTEGER DEFAULT 0,
    queue_depth INTEGER DEFAULT 0,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_system_metrics_recorded_at ON system_metrics(recorded_at DESC);
CREATE INDEX idx_system_metrics_cpu_usage ON system_metrics(cpu_usage_percent);
CREATE INDEX idx_system_metrics_memory_usage ON system_metrics(memory_usage_mb);

-- Performance Gate Table
CREATE TABLE performance_gates (
    gate_id TEXT PRIMARY KEY,
    metric_type TEXT NOT NULL CHECK (metric_type IN ('CPU', 'MEMORY', 'DISK_IO', 'NETWORK_IO', 'MTTD', 'FP_RATE')),
    threshold_value REAL NOT NULL,
    enforcement_action TEXT NOT NULL CHECK (enforcement_action IN ('ALERT', 'THROTTLE', 'BLOCK', 'DEGRADE')),
    enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_performance_gates_metric_type ON performance_gates(metric_type);
CREATE INDEX idx_performance_gates_enabled ON performance_gates(enabled);

-- Insert default performance gates
INSERT INTO performance_gates (gate_id, metric_type, threshold_value, enforcement_action) VALUES
('gate_cpu', 'CPU', 6.0, 'THROTTLE'),
('gate_memory', 'MEMORY', 200.0, 'DEGRADE'),
('gate_mttd', 'MTTD', 60.0, 'ALERT'),
('gate_fp_rate', 'FP_RATE', 0.1, 'BLOCK');

-- Insert default threat families
INSERT INTO threat_families (family_id, family_name, description) VALUES
('ransomware_generic', 'Ransomware.Generic', 'Generic ransomware detection patterns'),
('trojan_generic', 'Trojan.Generic', 'Generic trojan detection patterns'),
('backdoor_generic', 'Backdoor.Generic', 'Generic backdoor detection patterns'),
('rootkit_generic', 'Rootkit.Generic', 'Generic rootkit detection patterns');

-- Insert default rule families
INSERT INTO rule_families (family_id, family_name, description, provenance) VALUES
('yara_community', 'Community Rules', 'Open source community YARA rules', 'https://github.com/Yara-Rules/rules'),
('custom_internal', 'Internal Rules', 'Custom internal detection rules', 'Internal Development'),
('threat_intel', 'Threat Intelligence', 'Threat intelligence derived rules', 'Commercial Feed');