-- EMBER ML Malware Detection Database Schema
-- Migration 002: Add EMBER detection and automated response tables

-- EMBER Detections Table
-- Stores results from EMBER ML malware detection scans
CREATE TABLE IF NOT EXISTS ember_detections (
    detection_id TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_hash TEXT, -- SHA256 hash of the scanned file
    probability REAL NOT NULL CHECK (probability >= 0.0 AND probability <= 1.0),
    is_malware BOOLEAN NOT NULL,
    features TEXT NOT NULL, -- JSON array of extracted features
    model_version TEXT, -- Version of the EMBER model used
    threshold REAL NOT NULL, -- Threshold used for classification
    scan_duration_ms INTEGER, -- Time taken for the scan in milliseconds
    pe_features TEXT, -- JSON object with PE-specific features
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_id TEXT -- Reference to detection_scans table if integrated
    -- FOREIGN KEY (scan_id) REFERENCES detection_scans(scan_id) -- Disabled until detection_scans table is created
);

-- Indexes for ember_detections
CREATE INDEX IF NOT EXISTS idx_ember_detections_file_path ON ember_detections(file_path);
CREATE INDEX IF NOT EXISTS idx_ember_detections_is_malware ON ember_detections(is_malware);
CREATE INDEX IF NOT EXISTS idx_ember_detections_probability ON ember_detections(probability DESC);
CREATE INDEX IF NOT EXISTS idx_ember_detections_timestamp ON ember_detections(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ember_detections_file_hash ON ember_detections(file_hash);
CREATE INDEX IF NOT EXISTS idx_ember_detections_scan_id ON ember_detections(scan_id);

-- Response Actions Table
-- Stores automated response actions taken based on EMBER detections
CREATE TABLE IF NOT EXISTS response_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id TEXT NOT NULL, -- Reference to ember_detections
    file_path TEXT NOT NULL, -- File that triggered the response
    action_type TEXT NOT NULL CHECK (action_type IN ('QUARANTINE', 'ALERT', 'BLOCK', 'LOG', 'NOTIFY')),
    action_details TEXT, -- JSON object with action-specific details
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'EXECUTING', 'COMPLETED', 'FAILED', 'CANCELLED')) DEFAULT 'PENDING',
    error_message TEXT, -- Error details if action failed
    policy_name TEXT, -- Name of the policy that triggered this action
    policy_version TEXT, -- Version of the policy used
    execution_time_ms INTEGER, -- Time taken to execute the action
    quarantine_path TEXT, -- Path where file was quarantined (if applicable)
    original_permissions TEXT, -- Original file permissions (for restoration)
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME, -- When the action was completed
    FOREIGN KEY (detection_id) REFERENCES ember_detections(detection_id)
);

-- Indexes for response_actions
CREATE INDEX IF NOT EXISTS idx_response_actions_detection_id ON response_actions(detection_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_file_path ON response_actions(file_path);
CREATE INDEX IF NOT EXISTS idx_response_actions_action_type ON response_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);
CREATE INDEX IF NOT EXISTS idx_response_actions_timestamp ON response_actions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_response_actions_policy_name ON response_actions(policy_name);

-- Response Policies Table
-- Stores automated response policy configurations
CREATE TABLE IF NOT EXISTS response_policies (
    policy_id TEXT PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    description TEXT,
    version TEXT NOT NULL DEFAULT '1.0',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    policy_config TEXT NOT NULL, -- JSON configuration
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT, -- User or system that created the policy
    last_used DATETIME -- Last time this policy was applied
);

-- Indexes for response_policies
CREATE INDEX IF NOT EXISTS idx_response_policies_name ON response_policies(policy_name);
CREATE INDEX IF NOT EXISTS idx_response_policies_active ON response_policies(is_active);
CREATE INDEX IF NOT EXISTS idx_response_policies_updated_at ON response_policies(updated_at DESC);

-- EMBER Model Metadata Table
-- Stores information about EMBER models used
CREATE TABLE IF NOT EXISTS ember_models (
    model_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    model_path TEXT NOT NULL,
    model_version TEXT NOT NULL,
    model_hash TEXT, -- SHA256 hash of the model file
    feature_count INTEGER, -- Number of features the model expects
    accuracy_score REAL, -- Known accuracy of the model
    training_date DATE, -- When the model was trained
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used DATETIME -- Last time this model was used for detection
);

-- Indexes for ember_models
CREATE INDEX IF NOT EXISTS idx_ember_models_name ON ember_models(model_name);
CREATE INDEX IF NOT EXISTS idx_ember_models_active ON ember_models(is_active);
CREATE INDEX IF NOT EXISTS idx_ember_models_version ON ember_models(model_version);

-- EMBER Statistics Table
-- Stores aggregated statistics for EMBER detection performance
CREATE TABLE IF NOT EXISTS ember_statistics (
    stat_id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_recorded DATE NOT NULL,
    total_scans INTEGER NOT NULL DEFAULT 0,
    malware_detected INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    false_negatives INTEGER NOT NULL DEFAULT 0,
    avg_scan_time_ms REAL,
    avg_probability REAL,
    model_version TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for ember_statistics
CREATE INDEX IF NOT EXISTS idx_ember_statistics_date ON ember_statistics(date_recorded DESC);
CREATE INDEX IF NOT EXISTS idx_ember_statistics_model_version ON ember_statistics(model_version);

-- Insert default response policy
INSERT OR IGNORE INTO response_policies (policy_id, policy_name, description, policy_config) VALUES (
    'default_ember_policy',
    'Default EMBER Response Policy',
    'Default automated response policy for EMBER malware detections',
    '{
        "high_risk_threshold": 0.8,
        "medium_risk_threshold": 0.6,
        "actions": {
            "high_risk": ["quarantine", "alert"],
            "medium_risk": ["alert", "log"],
            "low_risk": ["log"]
        },
        "quarantine_settings": {
            "enabled": true,
            "preserve_permissions": true,
            "retention_days": 30
        },
        "alert_settings": {
            "enabled": true,
            "severity_mapping": {
                "high_risk": "CRITICAL",
                "medium_risk": "HIGH",
                "low_risk": "MEDIUM"
            }
        }
    }'
);

-- Insert default EMBER model entry (placeholder)
INSERT OR IGNORE INTO ember_models (model_id, model_name, model_path, model_version, feature_count) VALUES (
    'ember_lightgbm_v1',
    'EMBER LightGBM Model v1',
    './models/ember_model.onnx',
    '1.0.0',
    2381
);

-- Create views for common queries

-- View for recent malware detections with response actions
CREATE VIEW IF NOT EXISTS recent_malware_detections AS
SELECT 
    ed.detection_id,
    ed.file_path,
    ed.probability,
    ed.timestamp as detected_at,
    ra.action_type,
    ra.status as action_status,
    ra.completed_at as action_completed_at
FROM ember_detections ed
LEFT JOIN response_actions ra ON ed.detection_id = ra.detection_id
WHERE ed.is_malware = TRUE
ORDER BY ed.timestamp DESC;

-- View for detection statistics by day
CREATE VIEW IF NOT EXISTS daily_detection_stats AS
SELECT 
    DATE(timestamp) as detection_date,
    COUNT(*) as total_detections,
    SUM(CASE WHEN is_malware THEN 1 ELSE 0 END) as malware_count,
    AVG(probability) as avg_probability,
    AVG(scan_duration_ms) as avg_scan_time_ms
FROM ember_detections
GROUP BY DATE(timestamp)
ORDER BY detection_date DESC;

-- View for response action effectiveness
CREATE VIEW IF NOT EXISTS response_action_stats AS
SELECT 
    action_type,
    COUNT(*) as total_actions,
    SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as successful_actions,
    SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) as failed_actions,
    AVG(execution_time_ms) as avg_execution_time_ms
FROM response_actions
GROUP BY action_type;