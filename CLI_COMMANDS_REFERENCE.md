# ERDPS Agent CLI Commands Reference

**Version:** v0.1.0  
**Last Updated:** September 30, 2025  
**Target:** SOC Operations and Security Teams

---

## Quick Reference

| Command | Status | Purpose | Usage |
|---------|--------|---------|-------|
| `scan-enhanced` | ✅ | Enhanced file scanning | `.\erdps-agent.exe scan-enhanced [OPTIONS] <PATH>` |
| `multi-scan` | ✅ | Multi-layer detection | `.\erdps-agent.exe multi-scan [OPTIONS] <PATH>` |
| `list-rules` | ✅ | YARA rules management | `.\erdps-agent.exe list-rules [OPTIONS]` |
| `stats` | ✅ | Engine statistics | `.\erdps-agent.exe stats [OPTIONS]` |
| `show-metrics` | ✅ | Performance metrics | `.\erdps-agent.exe show-metrics [OPTIONS]` |
| `update-rules` | ✅ | Rule synchronization | `.\erdps-agent.exe update-rules [OPTIONS]` |
| `config-repo` | ✅ | Repository management | `.\erdps-agent.exe config-repo <COMMAND>` |
| `optimize-rules` | ✅ | Performance optimization | `.\erdps-agent.exe optimize-rules [OPTIONS]` |
| `ember-scan` | ✅ | ML malware detection | `.\erdps-agent.exe ember-scan --path <PATH> --ember-model <MODEL>` |
| `correlate` | ✅ | Alert correlation | `.\erdps-agent.exe correlate --scan-result <RESULT>` |
| `score-threats` | ✅ | ML threat scoring | `.\erdps-agent.exe score-threats --model-path <MODEL> --input <INPUT>` |
| `auto-response` | ✅ | Automated responses | `.\erdps-agent.exe auto-response --response-policy <POLICY>` |
| `validate-rules` | ⚠️ | Rule validation | `.\erdps-agent.exe validate-rules [OPTIONS]` |
| `--dashboard` | ❌ | Web dashboard | `.\erdps-agent.exe --dashboard` |
| `--scan-file` | ⚠️ | Direct file scan | `.\erdps-agent.exe --scan-file <FILE>` |

**Legend:** ✅ Fully Functional | ⚠️ Partially Working | ❌ Non-Functional

---

## Detailed Command Documentation

### 1. scan-enhanced - Enhanced File Scanning

**Purpose:** Perform comprehensive YARA-based file scanning with advanced options.

**Syntax:**
```bash
.\erdps-agent.exe scan-enhanced [OPTIONS] <PATH>
```

**Options:**
- `--performance-mode <MODE>` - Scanning performance mode
  - Values: `fast`, `balanced`, `thorough`
  - Default: `balanced`
- `--category <CATEGORY>` - Filter rules by category
- `--optimize-rules` - Enable rule optimization
- `--parallel` - Enable parallel scanning
- `--output-format <FORMAT>` - Output format
  - Values: `table`, `json`
  - Default: `table`

**Examples:**
```bash
# Basic file scan
.\erdps-agent.exe scan-enhanced .\test_file.txt

# Fast scan with JSON output
.\erdps-agent.exe scan-enhanced --performance-mode fast --output-format json .\suspicious_file.exe

# Thorough scan with rule optimization
.\erdps-agent.exe scan-enhanced --performance-mode thorough --optimize-rules .\malware_sample.bin
```

**Output:**
- Scan results with match details
- Performance metrics
- Rule compilation statistics

---

### 2. multi-scan - Multi-Layer Detection

**Purpose:** Execute comprehensive multi-layer scanning across file, memory, behavior, and network layers.

**Syntax:**
```bash
.\erdps-agent.exe multi-scan [OPTIONS] <PATH>
```

**Options:**
- `--risk-threshold <THRESHOLD>` - Risk score threshold (0.0-1.0)
  - Default: `0.5`
- `--output-format <FORMAT>` - Output format
  - Values: `table`, `json`
  - Default: `table`
- `--layers <LAYERS>` - Specify detection layers
  - Values: `file`, `memory`, `behavior`, `network`
  - Default: All layers

**Examples:**
```bash
# Full multi-layer scan
.\erdps-agent.exe multi-scan .\target_file.exe

# High-sensitivity scan
.\erdps-agent.exe multi-scan --risk-threshold 0.2 .\suspicious_process.exe

# File and memory layers only
.\erdps-agent.exe multi-scan --layers file,memory .\sample.bin
```

**Output:**
- Risk score (0.0-1.0)
- Layer-specific results
- Match count per layer
- Total scan time

---

### 3. list-rules - YARA Rules Management

**Purpose:** Display and manage YARA rules in the database.

**Syntax:**
```bash
.\erdps-agent.exe list-rules [OPTIONS]
```

**Options:**
- `--category <CATEGORY>` - Filter by rule category
- `--repository <REPO>` - Filter by repository
- `--output-format <FORMAT>` - Output format
  - Values: `table`, `json`, `csv`
  - Default: `table`
- `--detailed` - Show detailed rule information

**Examples:**
```bash
# List all rules
.\erdps-agent.exe list-rules

# List rules by category
.\erdps-agent.exe list-rules --category malware

# Detailed JSON output
.\erdps-agent.exe list-rules --detailed --output-format json
```

**Output:**
- Rule names and categories
- Repository information
- Rule statistics
- Compilation status

---

### 4. stats - Engine Statistics

**Purpose:** Display YARA engine and database statistics.

**Syntax:**
```bash
.\erdps-agent.exe stats [OPTIONS]
```

**Options:**
- `--output-format <FORMAT>` - Output format
  - Values: `table`, `json`
  - Default: `table`
- `--detailed` - Show detailed statistics

**Examples:**
```bash
# Basic statistics
.\erdps-agent.exe stats

# Detailed JSON statistics
.\erdps-agent.exe stats --detailed --output-format json
```

**Output:**
- Total rules count
- Valid/invalid rules
- Repository count
- Database size
- Validation statistics

---

### 5. show-metrics - Performance Metrics

**Purpose:** Display rule compilation and performance metrics.

**Syntax:**
```bash
.\erdps-agent.exe show-metrics [OPTIONS]
```

**Options:**
- `--top <N>` - Show top N slowest rules
  - Default: `10`
- `--output-format <FORMAT>` - Output format
  - Values: `table`, `json`
  - Default: `table`

**Examples:**
```bash
# Show top 10 slowest rules
.\erdps-agent.exe show-metrics

# Show top 5 with JSON output
.\erdps-agent.exe show-metrics --top 5 --output-format json
```

**Output:**
- Rule compilation times
- Performance rankings
- Optimization recommendations

---

### 6. update-rules - Rule Synchronization

**Purpose:** Synchronize YARA rules from configured GitHub repositories.

**Syntax:**
```bash
.\erdps-agent.exe update-rules [OPTIONS]
```

**Options:**
- `--repository <REPO>` - Update specific repository
- `--force` - Force update even if up-to-date
- `--validate` - Validate rules after update

**Examples:**
```bash
# Update all repositories
.\erdps-agent.exe update-rules

# Force update specific repository
.\erdps-agent.exe update-rules --repository malware-rules --force

# Update with validation
.\erdps-agent.exe update-rules --validate
```

**Output:**
- Update status per repository
- New rules added
- Validation results

---

### 7. config-repo - Repository Management

**Purpose:** Manage YARA rule repositories.

**Syntax:**
```bash
.\erdps-agent.exe config-repo <COMMAND>
```

**Commands:**
- `add <URL>` - Add new repository
- `remove <NAME>` - Remove repository
- `list` - List configured repositories
- `enable <NAME>` - Enable repository
- `disable <NAME>` - Disable repository

**Examples:**
```bash
# Add repository
.\erdps-agent.exe config-repo add https://github.com/example/yara-rules.git

# List repositories
.\erdps-agent.exe config-repo list

# Enable/disable repository
.\erdps-agent.exe config-repo enable malware-rules
.\erdps-agent.exe config-repo disable test-rules
```

**Output:**
- Repository status
- Configuration changes
- Validation results

---

### 8. optimize-rules - Performance Optimization

**Purpose:** Optimize YARA rules for performance and deduplication.

**Syntax:**
```bash
.\erdps-agent.exe optimize-rules [OPTIONS]
```

**Options:**
- `--performance-threshold <MS>` - Performance threshold in milliseconds
  - Default: `100`
- `--dry-run` - Show optimization plan without applying
- `--deduplicate` - Remove duplicate rules

**Examples:**
```bash
# Basic optimization
.\erdps-agent.exe optimize-rules

# Dry run with custom threshold
.\erdps-agent.exe optimize-rules --performance-threshold 50 --dry-run

# Full optimization with deduplication
.\erdps-agent.exe optimize-rules --deduplicate
```

**Output:**
- Optimization statistics
- Performance improvements
- Deduplication results

---

### 9. ember-scan - ML Malware Detection

**Purpose:** Perform machine learning-based malware detection using EMBER models.

**Syntax:**
```bash
.\erdps-agent.exe ember-scan --path <PATH> --ember-model <MODEL>
```

**Required Options:**
- `--path <PATH>` - File or directory to scan
- `--ember-model <MODEL>` - Path to ONNX model file

**Optional Options:**
- `--threshold <THRESHOLD>` - Detection threshold (0.0-1.0)
  - Default: `0.5`
- `--auto-response` - Enable automated response

**Examples:**
```bash
# Basic EMBER scan
.\erdps-agent.exe ember-scan --path .\sample.exe --ember-model .\models\ember.onnx

# High-sensitivity scan with auto-response
.\erdps-agent.exe ember-scan --path .\suspicious\ --ember-model .\models\ember.onnx --threshold 0.3 --auto-response
```

**Output:**
- ML prediction scores
- Classification results
- Feature extraction details

---

### 10. correlate - Alert Correlation

**Purpose:** Correlate alerts from multiple detection layers.

**Syntax:**
```bash
.\erdps-agent.exe correlate --scan-result <RESULT>
```

**Required Options:**
- `--scan-result <RESULT>` - Path to scan result file (JSON)

**Optional Options:**
- `--correlation-threshold <THRESHOLD>` - Correlation threshold
- `--output-format <FORMAT>` - Output format

**Examples:**
```bash
# Correlate scan results
.\erdps-agent.exe correlate --scan-result .\results\multi_scan_output.json

# Custom correlation threshold
.\erdps-agent.exe correlate --scan-result .\results\scan.json --correlation-threshold 0.7
```

**Output:**
- Correlated alerts
- Confidence scores
- Relationship analysis

---

### 11. score-threats - ML Threat Scoring

**Purpose:** Score threats using machine learning models.

**Syntax:**
```bash
.\erdps-agent.exe score-threats --model-path <MODEL> --input <INPUT>
```

**Required Options:**
- `--model-path <MODEL>` - Path to ML model file
- `--input <INPUT>` - Input data file (JSON)

**Optional Options:**
- `--feature-scaling` - Enable feature scaling
- `--output-format <FORMAT>` - Output format

**Examples:**
```bash
# Basic threat scoring
.\erdps-agent.exe score-threats --model-path .\models\threat_model.onnx --input .\data\features.json

# With feature scaling
.\erdps-agent.exe score-threats --model-path .\models\model.onnx --input .\data\input.json --feature-scaling
```

**Output:**
- Threat scores
- Risk classifications
- Model predictions

---

### 12. auto-response - Automated Response

**Purpose:** Execute automated response policies based on detection results.

**Syntax:**
```bash
.\erdps-agent.exe auto-response --response-policy <POLICY>
```

**Required Options:**
- `--response-policy <POLICY>` - Path to response policy file

**Optional Options:**
- `--dry-run` - Show actions without executing
- `--log-level <LEVEL>` - Logging level

**Examples:**
```bash
# Execute response policy
.\erdps-agent.exe auto-response --response-policy .\policies\malware_response.json

# Dry run mode
.\erdps-agent.exe auto-response --response-policy .\policies\policy.json --dry-run
```

**Output:**
- Executed actions
- Policy compliance
- Response results

---

## Partially Functional Commands

### 13. validate-rules - Rule Validation ⚠️

**Purpose:** Validate YARA rules for syntax and compilation errors.

**Status:** Partially functional - reports validation failures on test rules.

**Syntax:**
```bash
.\erdps-agent.exe validate-rules [OPTIONS]
```

**Known Issues:**
- Validation failures on existing test rules
- Error: "Failed to add rule to compiler"

**Recommended Action:** Review rule syntax before using in production.

---

## Non-Functional Commands

### 14. --dashboard - Web Dashboard ❌

**Purpose:** Launch web-based dashboard interface.

**Status:** Non-functional due to configuration error.

**Syntax:**
```bash
.\erdps-agent.exe --dashboard
```

**Error:** "Invalid dashboard bind address: invalid socket address syntax"

**Required Fix:** Review dashboard configuration in config.toml

---

### 15. --scan-file - Direct File Scanning ⚠️

**Purpose:** Direct file scanning via agent service.

**Status:** Requires running agent service.

**Syntax:**
```bash
.\erdps-agent.exe --scan-file <FILE>
```

**Error:** Connection refused to agent service (127.0.0.1:19091)

**Workaround:** Start agent service first, then use this command.

---

## Global Options

All commands support these global options:

- `--help` - Display command help
- `--version` - Show version information
- `--config <CONFIG>` - Specify configuration file
- `--verbose` - Enable verbose logging
- `--quiet` - Suppress non-essential output

---

## Configuration Files

### Primary Configuration
- **File:** `config.toml`
- **Location:** Agent root directory
- **Purpose:** Main agent configuration

### Rule Repositories
- **File:** `repositories.json`
- **Location:** `config/` directory
- **Purpose:** Repository configuration

### Response Policies
- **Directory:** `policies/`
- **Format:** JSON
- **Purpose:** Automated response definitions

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Validation error |
| 4 | Network error |
| 5 | File system error |

---

## Best Practices

### For SOC Operations:

1. **Regular Rule Updates:**
   ```bash
   .\erdps-agent.exe update-rules --validate
   ```

2. **Performance Monitoring:**
   ```bash
   .\erdps-agent.exe show-metrics --top 20
   ```

3. **Multi-Layer Scanning:**
   ```bash
   .\erdps-agent.exe multi-scan --risk-threshold 0.3 <target>
   ```

4. **Automated Response:**
   ```bash
   .\erdps-agent.exe auto-response --response-policy .\policies\soc_policy.json
   ```

### For Incident Response:

1. **Enhanced Scanning:**
   ```bash
   .\erdps-agent.exe scan-enhanced --performance-mode thorough --optimize-rules <evidence>
   ```

2. **ML Analysis:**
   ```bash
   .\erdps-agent.exe ember-scan --path <sample> --ember-model <model> --threshold 0.2
   ```

3. **Alert Correlation:**
   ```bash
   .\erdps-agent.exe correlate --scan-result <results.json>
   ```

---

## Troubleshooting

### Common Issues:

1. **No Rules Loaded:**
   - Configure repositories: `config-repo add <url>`
   - Update rules: `update-rules`

2. **Dashboard Not Starting:**
   - Check config.toml dashboard settings
   - Verify bind address configuration

3. **Validation Failures:**
   - Review rule syntax
   - Check YARA compiler compatibility

4. **Connection Errors:**
   - Ensure agent service is running
   - Verify port availability (19091, 19094)

---

*End of CLI Reference*

**Document Version:** v0.1.0  
**Last Updated:** September 30, 2025  
**Maintained By:** ERDPS Development Team