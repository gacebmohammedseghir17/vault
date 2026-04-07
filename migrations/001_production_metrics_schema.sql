-- Production Metrics and Validation Tracking Database Schema
-- This schema supports comprehensive monitoring and validation for ERDPS Phase 2

-- Performance Metrics Table
-- Tracks system performance metrics for production monitoring
CREATE TABLE IF NOT EXISTS performance_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metric_type VARCHAR(50) NOT NULL, -- 'cpu_usage', 'memory_usage', 'scan_duration', 'throughput'
    metric_value REAL NOT NULL,
    unit VARCHAR(20) NOT NULL, -- 'percent', 'mb', 'seconds', 'files_per_second'
    component VARCHAR(50) NOT NULL, -- 'behavioral_engine', 'pattern_matcher', 'yara_scanner'
    process_id INTEGER,
    additional_context TEXT, -- JSON string for additional metadata
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Detection Results Table
-- Stores all detection results for analysis and validation
CREATE TABLE IF NOT EXISTS detection_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    detection_id VARCHAR(36) NOT NULL UNIQUE, -- UUID for tracking
    detection_type VARCHAR(50) NOT NULL, -- 'ransomware', 'malware', 'behavioral_anomaly'
    confidence_score REAL NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    threat_level VARCHAR(20) NOT NULL, -- 'low', 'medium', 'high', 'critical'
    file_path TEXT,
    file_hash VARCHAR(64),
    file_size INTEGER,
    process_id INTEGER,
    process_name VARCHAR(255),
    detection_engine VARCHAR(50) NOT NULL, -- 'yara', 'behavioral', 'pattern_matcher'
    rule_name VARCHAR(100),
    mitigation_applied BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    validated BOOLEAN DEFAULT FALSE,
    validation_timestamp DATETIME,
    validation_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Validation Tracking Table
-- Tracks validation results and test outcomes
CREATE TABLE IF NOT EXISTS validation_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    test_suite VARCHAR(50) NOT NULL, -- 'performance_gates', 'behavioral_validation', 'integration'
    test_name VARCHAR(100) NOT NULL,
    test_status VARCHAR(20) NOT NULL, -- 'passed', 'failed', 'skipped', 'error'
    execution_time_ms INTEGER,
    expected_result TEXT,
    actual_result TEXT,
    error_message TEXT,
    test_environment VARCHAR(50), -- 'development', 'staging', 'production'
    build_version VARCHAR(50),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- System Health Metrics Table
-- Tracks overall system health and availability
CREATE TABLE IF NOT EXISTS system_health (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    component VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'healthy', 'degraded', 'critical', 'offline'
    uptime_seconds INTEGER,
    error_count INTEGER DEFAULT 0,
    warning_count INTEGER DEFAULT 0,
    last_error_message TEXT,
    last_error_timestamp DATETIME,
    memory_usage_mb REAL,
    cpu_usage_percent REAL,
    disk_usage_mb REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Performance Gates Table
-- Stores performance gate thresholds and results
CREATE TABLE IF NOT EXISTS performance_gates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    gate_name VARCHAR(100) NOT NULL,
    gate_type VARCHAR(50) NOT NULL, -- 'cpu_threshold', 'memory_threshold', 'duration_threshold'
    threshold_value REAL NOT NULL,
    actual_value REAL NOT NULL,
    passed BOOLEAN NOT NULL,
    component VARCHAR(50) NOT NULL,
    test_context VARCHAR(100),
    severity VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log Table
-- Comprehensive audit trail for security and compliance
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(50) NOT NULL, -- 'detection', 'mitigation', 'configuration_change', 'system_event'
    user_id VARCHAR(50),
    component VARCHAR(50) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_affected TEXT,
    old_value TEXT,
    new_value TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id VARCHAR(100),
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for Performance Optimization
CREATE INDEX IF NOT EXISTS idx_performance_metrics_timestamp ON performance_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_component ON performance_metrics(component);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_type ON performance_metrics(metric_type);

CREATE INDEX IF NOT EXISTS idx_detection_results_timestamp ON detection_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_detection_results_type ON detection_results(detection_type);
CREATE INDEX IF NOT EXISTS idx_detection_results_confidence ON detection_results(confidence_score);
CREATE INDEX IF NOT EXISTS idx_detection_results_engine ON detection_results(detection_engine);
CREATE INDEX IF NOT EXISTS idx_detection_results_validated ON detection_results(validated);

CREATE INDEX IF NOT EXISTS idx_validation_tracking_timestamp ON validation_tracking(timestamp);
CREATE INDEX IF NOT EXISTS idx_validation_tracking_suite ON validation_tracking(test_suite);
CREATE INDEX IF NOT EXISTS idx_validation_tracking_status ON validation_tracking(test_status);

CREATE INDEX IF NOT EXISTS idx_system_health_timestamp ON system_health(timestamp);
CREATE INDEX IF NOT EXISTS idx_system_health_component ON system_health(component);
CREATE INDEX IF NOT EXISTS idx_system_health_status ON system_health(status);

CREATE INDEX IF NOT EXISTS idx_performance_gates_timestamp ON performance_gates(timestamp);
CREATE INDEX IF NOT EXISTS idx_performance_gates_passed ON performance_gates(passed);
CREATE INDEX IF NOT EXISTS idx_performance_gates_component ON performance_gates(component);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_component ON audit_log(component);

-- Views for Common Queries

-- Performance Summary View
CREATE VIEW IF NOT EXISTS performance_summary AS
SELECT 
    component,
    metric_type,
    AVG(metric_value) as avg_value,
    MIN(metric_value) as min_value,
    MAX(metric_value) as max_value,
    COUNT(*) as sample_count,
    DATE(timestamp) as date
FROM performance_metrics 
WHERE timestamp >= datetime('now', '-7 days')
GROUP BY component, metric_type, DATE(timestamp)
ORDER BY date DESC, component, metric_type;

-- Detection Summary View
CREATE VIEW IF NOT EXISTS detection_summary AS
SELECT 
    detection_type,
    detection_engine,
    threat_level,
    COUNT(*) as detection_count,
    AVG(confidence_score) as avg_confidence,
    SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) as false_positive_count,
    SUM(CASE WHEN validated = 1 THEN 1 ELSE 0 END) as validated_count,
    DATE(timestamp) as date
FROM detection_results 
WHERE timestamp >= datetime('now', '-30 days')
GROUP BY detection_type, detection_engine, threat_level, DATE(timestamp)
ORDER BY date DESC, detection_count DESC;

-- System Health Summary View
CREATE VIEW IF NOT EXISTS system_health_summary AS
SELECT 
    component,
    status,
    COUNT(*) as status_count,
    AVG(cpu_usage_percent) as avg_cpu,
    AVG(memory_usage_mb) as avg_memory,
    MAX(error_count) as max_errors,
    DATE(timestamp) as date
FROM system_health 
WHERE timestamp >= datetime('now', '-7 days')
GROUP BY component, status, DATE(timestamp)
ORDER BY date DESC, component;

-- Performance Gates Summary View
CREATE VIEW IF NOT EXISTS performance_gates_summary AS
SELECT 
    gate_name,
    gate_type,
    component,
    COUNT(*) as total_checks,
    SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_checks,
    ROUND(100.0 * SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) as pass_rate,
    AVG(actual_value) as avg_actual_value,
    AVG(threshold_value) as avg_threshold_value,
    DATE(timestamp) as date
FROM performance_gates 
WHERE timestamp >= datetime('now', '-30 days')
GROUP BY gate_name, gate_type, component, DATE(timestamp)
ORDER BY date DESC, pass_rate ASC;

-- Insert initial configuration data
INSERT OR IGNORE INTO performance_gates (gate_name, gate_type, threshold_value, actual_value, passed, component, test_context) VALUES
('CPU Usage Threshold', 'cpu_threshold', 5.0, 0.0, 1, 'system', 'Initial configuration'),
('Memory Usage Threshold', 'memory_threshold', 200.0, 0.0, 1, 'system', 'Initial configuration'),
('Scan Duration Threshold', 'duration_threshold', 30.0, 0.0, 1, 'pattern_matcher', 'Initial configuration'),
('Behavioral Analysis Duration', 'duration_threshold', 5.0, 0.0, 1, 'behavioral_engine', 'Initial configuration'),
('YARA Scan Duration', 'duration_threshold', 10.0, 0.0, 1, 'yara_scanner', 'Initial configuration');

-- Insert initial system health status
INSERT OR IGNORE INTO system_health (component, status, uptime_seconds, error_count, warning_count) VALUES
('behavioral_engine', 'healthy', 0, 0, 0),
('pattern_matcher', 'healthy', 0, 0, 0),
('yara_scanner', 'healthy', 0, 0, 0),
('api_hooking', 'healthy', 0, 0, 0),
('network_monitor', 'healthy', 0, 0, 0);