# ERDPS Agent - YARA Module

The Enhanced Ransomware Detection and Prevention System (ERDPS) Agent's YARA module provides advanced malware detection capabilities with category-based filtering and enhanced scanning features.

## Features

- **Enhanced YARA Scanning**: Advanced scanning pipeline with performance optimization
- **Category-Based Filtering**: Filter rules by categories during scanning
- **Async/Await Support**: Full asynchronous scanning for better performance
- **Rule Management**: Comprehensive rule storage and management system
- **Performance Metrics**: Detailed scanning performance tracking
- **Cross-Platform**: Compatible with Windows and Linux systems

## Installation

Ensure you have Rust 1.70 or later installed:

```bash
rustc --version  # Should be 1.70.0 or later
```

### Basic Installation

Build the project without network monitoring features:

```bash
cargo build --release --no-default-features --features "basic-detection,metrics,yara,validation-framework,advanced-logging,behavioral-analysis,automated-response,memory-forensics,api-hooking,performance-optimization"
```

### Full Installation (with Network Monitoring)

For network monitoring capabilities, additional dependencies are required:

1. **Install Npcap or WinPcap** (see [Network Monitoring Setup Guide](NETWORK_MONITORING_SETUP.md))
2. Build with all features:

```bash
cargo build --release
```

**Note**: If you encounter `cannot open input file 'Packet.lib'` errors, see the [Network Monitoring Setup Guide](NETWORK_MONITORING_SETUP.md) for dependency installation instructions.

## Usage

### Enhanced Scanning with Category Filtering

The `scan-enhanced` command provides advanced scanning capabilities with optional category filtering:

```bash
# Basic enhanced scan
cargo run -- scan-enhanced /path/to/scan

# Scan with specific categories only
cargo run -- scan-enhanced /path/to/scan --include-categories ransomware,apt,banking

# Scan excluding certain categories
cargo run -- scan-enhanced /path/to/scan --exclude-categories test,experimental

# Combine include and exclude filters
cargo run -- scan-enhanced /path/to/scan --include-categories ransomware,apt --exclude-categories test
```

#### Category Filtering Options

- `--include-categories <CATEGORIES>`: Comma-separated list of categories to include in the scan
  - If specified, only rules matching these categories will be used
  - If not specified, all categories are included by default
  - Example: `--include-categories ransomware,apt,malware`

- `--exclude-categories <CATEGORIES>`: Comma-separated list of categories to exclude from the scan
  - Rules matching these categories will be skipped
  - Exclude filters take precedence over include filters
  - Example: `--exclude-categories test,experimental,debug`

#### Common Category Examples

- `ransomware`: Ransomware detection rules
- `apt`: Advanced Persistent Threat rules
- `malware`: General malware detection rules
- `banking`: Banking trojan detection rules
- `trojan`: Trojan detection rules
- `spyware`: Spyware detection rules
- `test`: Test rules (often excluded in production)
- `experimental`: Experimental rules (may have false positives)

### Other Commands

```bash
# List all available rules
cargo run -- list-rules

# Update rule database
cargo run -- update-rules

# Validate rules
cargo run -- validate-rules

# Optimize rules for performance
cargo run -- optimize-rules

# Show scanning metrics
cargo run -- show-metrics
```

## Configuration

### Environment Variables

- `YARA_RULES_PATH`: Path to YARA rules directory (default: `./rules`)
- `YARA_DB_PATH`: Path to rule database (default: `./yara.db`)
- `LOG_LEVEL`: Logging level (default: `info`)

### Logging

The module provides detailed logging for category filtering:

- **Info Level**: Reports when rules are skipped due to category filtering
- **Debug Level**: Shows rule count statistics (total vs filtered)
- **Trace Level**: Detailed rule processing information

Example log output:
```
[INFO] Skipping rule malware_rule_001 category=test
[DEBUG] Category filtering: 1500 total rules, 850 after filtering
```

## Architecture

### Core Components

- **CategoryFilter** (`src/yara/category_scanner.rs`): Handles category-based rule filtering
- **EnhancedScanner** (`src/yara/enhanced_scanner.rs`): Main scanning engine with async support
- **CLI Commands** (`src/yara/cli_commands.rs`): Command-line interface implementation
- **Category System** (`src/yara/category_system.rs`): Rule categorization and metadata management

### Category Filtering Logic

1. **Load Active Rules**: Retrieve all active rules from the database
2. **Apply Include Filter**: If include categories are specified, only keep rules matching those categories
3. **Apply Exclude Filter**: Remove any rules matching exclude categories
4. **Execute Scan**: Run the filtered rule set against target files

The filtering logic follows this precedence:
- If no include categories are specified, all categories are included by default
- Exclude categories always take precedence over include categories
- Category matching is case-sensitive

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run category filter tests specifically
cargo test category_scanner

# Run with verbose output
cargo test -- --nocapture
```

### Code Structure

```
src/yara/
├── category_scanner.rs    # Category filtering implementation
├── enhanced_scanner.rs    # Main scanning engine
├── cli_commands.rs        # CLI interface
├── category_system.rs     # Rule categorization
└── mod.rs                 # Module declarations

tests/
└── category_scanner_tests.rs  # Category filter unit tests
```

### Adding New Categories

1. Update rule metadata in the database with the new category
2. Rules are automatically available for filtering once categorized
3. No code changes required for new categories

### Performance Considerations

- Category filtering happens before rule compilation for optimal performance
- Filtered rules are not loaded into memory, reducing resource usage
- Async scanning pipeline maintains responsiveness during large scans
- Rule caching minimizes database queries

## Compatibility

- **Rust Version**: 1.70 or later
- **Operating Systems**: Windows 10/11, Linux (Ubuntu 20.04+, CentOS 8+)
- **Architecture**: x86_64, ARM64
- **YARA Version**: 4.0 or later

## Troubleshooting

### Common Issues

1. **No rules loaded after filtering**:
   - Check that your include categories match existing rule categories
   - Verify rule metadata in the database
   - Use `cargo run -- list-rules` to see available categories

2. **Performance issues with large rule sets**:
   - Use category filtering to reduce the active rule set
   - Consider excluding test/experimental categories in production
   - Monitor memory usage with large file scans

3. **Category case sensitivity**:
   - Ensure category names match exactly (case-sensitive)
   - Check rule metadata for correct category spelling

### Debug Mode

Enable debug logging for detailed filtering information:

```bash
RUST_LOG=debug cargo run -- scan-enhanced /path/to/scan --include-categories ransomware
```

## Contributing

1. Follow Rust coding standards and conventions
2. Add tests for new functionality
3. Update documentation for API changes
4. Ensure compatibility with Rust 1.70+
5. Test on both Windows and Linux platforms

## License

This project is part of the ERDPS system. See LICENSE file for details.