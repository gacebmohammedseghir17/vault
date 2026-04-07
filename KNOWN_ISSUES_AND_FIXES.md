# ERDPS Agent Known Issues and Recommended Fixes

**Version:** v0.1.0  
**Last Updated:** September 30, 2025  
**Priority Classification:** Critical | Medium | Low

---

## Executive Summary

This document outlines all identified issues in the ERDPS agent based on comprehensive functionality testing. Issues are categorized by severity and include specific remediation steps for SOC deployment readiness.

**Overall Status:** 20 failing tests out of 439 total (95.4% pass rate)

---

## Critical Issues (Must Fix Before Production)

### 1. Dashboard Configuration Error ❌

**Issue ID:** CRIT-001  
**Component:** Web Dashboard  
**Severity:** Critical  

**Description:**
Dashboard fails to start due to invalid bind address configuration.

**Error Message:**
```
Error: "Invalid dashboard bind address: invalid socket address syntax"
```

**Impact:**
- Web interface completely non-functional
- No visual monitoring capabilities
- SOC teams cannot access dashboard

**Root Cause:**
Configuration parsing error in `config.toml` dashboard section.

**Recommended Fix:**
1. Review dashboard configuration in `config.toml`
2. Validate bind address format (should be `IP:PORT`)
3. Ensure port availability (default: 19094)
4. Test configuration syntax

**Implementation Steps:**
```bash
# Check current configuration
cat config.toml | grep -A 5 "\[dashboard\]"

# Validate port availability
netstat -an | findstr :19094

# Test configuration
.\erdps-agent.exe --config config.toml --validate-config
```

**Priority:** HIGH - Blocks SOC dashboard functionality

---

### 2. YARA Rule Validation Failures ❌

**Issue ID:** CRIT-002  
**Component:** YARA Engine  
**Severity:** Critical  

**Description:**
YARA rule validation consistently fails on test rules, preventing rule compilation.

**Error Message:**
```
Error: "Failed to add rule to compiler"
YARA command failed: Failed to validate rules
```

**Impact:**
- Cannot validate rule syntax
- Risk of deploying invalid rules
- Potential runtime compilation failures

**Root Cause:**
Rule syntax incompatibility or YARA compiler version mismatch.

**Recommended Fix:**
1. Validate YARA rule syntax in `rules/test_rules.yar`
2. Check YARA compiler version compatibility
3. Review rule compilation process
4. Update rule syntax if needed

**Implementation Steps:**
```bash
# Manual YARA validation
yara-compiler --version
yara-compiler rules/test_rules.yar

# Check rule syntax
.\erdps-agent.exe validate-rules --verbose --rules-path rules/test_rules.yar
```

**Priority:** HIGH - Affects core detection capabilities

---

### 3. Zero Rules Loaded ❌

**Issue ID:** CRIT-003  
**Component:** Rule Management  
**Severity:** Critical  

**Description:**
No YARA rules currently loaded in the system (Total: 0 rules).

**Error Message:**
```
Total rules: 0
Valid rules: 0
Invalid rules: 0
```

**Impact:**
- No detection capabilities
- All scans return zero matches
- System effectively non-functional for detection

**Root Cause:**
No repositories configured or rules not properly loaded from repositories.

**Recommended Fix:**
1. Configure YARA rule repositories
2. Download and validate rule sets
3. Ensure proper rule loading process

**Implementation Steps:**
```bash
# Add rule repository
.\erdps-agent.exe config-repo add https://github.com/Yara-Rules/rules.git

# Update rules from repositories
.\erdps-agent.exe update-rules --force

# Verify rule loading
.\erdps-agent.exe list-rules
.\erdps-agent.exe stats
```

**Priority:** HIGH - System has no detection capability without rules

---

## Medium Priority Issues

### 4. EMBER ML Test Failures ⚠️

**Issue ID:** MED-001  
**Component:** EMBER Integration  
**Severity:** Medium  

**Description:**
3 out of 23 EMBER ML tests failing, affecting machine learning detection capabilities.

**Failing Tests:**
- `test_feature_extraction_error_handling`
- `test_pe_feature_extraction`
- `test_error_recovery_and_resilience`

**Error Details:**
```
assertion failed: Feature extraction should handle errors gracefully
assertion failed: PE feature extraction validation failed
assertion failed: Error recovery mechanism not working as expected
```

**Impact:**
- Reduced ML detection accuracy
- Potential crashes during feature extraction
- Unreliable error handling in ML pipeline

**Root Cause:**
Feature extraction validation logic or test expectations mismatch.

**Recommended Fix:**
1. Review EMBER integration test expectations
2. Validate feature extraction process
3. Improve error handling in ML pipeline
4. Update test assertions if needed

**Implementation Steps:**
```bash
# Run specific failing tests with verbose output
cargo test --test ember_response_tests test_feature_extraction_error_handling -- --nocapture

# Check EMBER model compatibility
.\erdps-agent.exe ember-scan --path test_file.exe --ember-model models/test.onnx --verbose
```

**Priority:** MEDIUM - Affects ML detection but core functionality remains

---

### 5. Integration Test Compilation Errors ⚠️

**Issue ID:** MED-002  
**Component:** Test Framework  
**Severity:** Medium  

**Description:**
Integration tests fail to compile due to async/await syntax issues and feature flag dependencies.

**Error Messages:**
```
E0277: `Result<(), anyhow::Error>` is not a future
E0061: missing argument for `NetworkMonitor::new`
E0308: mismatched types for `network_monitor`
```

**Impact:**
- Cannot run comprehensive integration tests
- Reduced test coverage
- Potential integration issues undetected

**Root Cause:**
Test framework not updated for async compatibility and missing feature flags.

**Recommended Fix:**
1. Update test framework for async compatibility
2. Add required feature flags to test configuration
3. Fix async/await syntax in test functions
4. Resolve type mismatches

**Implementation Steps:**
```bash
# Run with required features
cargo test --test integration_tests --features "comprehensive-testing,behavioral-analysis,network-monitoring,api-hooking,yara,advanced-detection"

# Check async function signatures
grep -r "async fn" tests/integration_tests.rs
```

**Priority:** MEDIUM - Affects testing but not runtime functionality

---

### 6. False Positive Test Framework Issues ⚠️

**Issue ID:** MED-003  
**Component:** Test Framework  
**Severity:** Medium  

**Description:**
False positive tests fail due to network monitor initialization and type mismatches.

**Error Messages:**
```
E0061: missing argument for `NetworkMonitor::new`
E0308: mismatched types for `network_monitor`
E0599: no `start_monitoring` or `stop_monitoring` methods found
```

**Impact:**
- Cannot validate false positive rates
- Potential for high false positive rates in production
- Reduced confidence in detection accuracy

**Root Cause:**
Test framework API changes not reflected in test code.

**Recommended Fix:**
1. Update test framework API calls
2. Fix network monitor initialization
3. Resolve method signature mismatches
4. Validate false positive testing methodology

**Implementation Steps:**
```bash
# Check network monitor API
grep -r "NetworkMonitor::new" src/
grep -r "start_monitoring\|stop_monitoring" src/

# Update test with correct API
cargo test --test false_positive --features "testing,telemetry,behavioral-analysis,yara"
```

**Priority:** MEDIUM - Important for production validation

---

## Low Priority Issues

### 7. File System Monitoring Warnings ⚠️

**Issue ID:** LOW-001  
**Component:** Behavioral Analysis  
**Severity:** Low  

**Description:**
File system monitoring generates warnings for legacy Windows paths.

**Error Message:**
```
Error: Path not found: "C:\\Documents and Settings"
```

**Impact:**
- Log noise and unnecessary warnings
- Potential performance impact from failed path checks
- Confusion in log analysis

**Root Cause:**
Legacy path validation for older Windows versions.

**Recommended Fix:**
1. Update path validation for modern Windows systems
2. Add OS version detection
3. Filter out legacy paths on newer systems
4. Improve error handling for missing paths

**Implementation Steps:**
```bash
# Check OS version detection
systeminfo | findstr "OS Name"

# Review path validation logic
grep -r "Documents and Settings" src/
```

**Priority:** LOW - Cosmetic issue, doesn't affect functionality

---

### 8. Agent Service Connection Dependency ⚠️

**Issue ID:** LOW-002  
**Component:** CLI Interface  
**Severity:** Low  

**Description:**
`--scan-file` command requires running agent service, creating dependency.

**Error Message:**
```
Connection refused to agent service (127.0.0.1:19091)
```

**Impact:**
- Command only works when service is running
- Inconsistent CLI behavior
- Additional complexity for users

**Root Cause:**
Design decision to route some commands through service API.

**Recommended Fix:**
1. Add standalone mode for file scanning
2. Improve error messages with guidance
3. Document service dependency clearly
4. Consider command consolidation

**Implementation Steps:**
```bash
# Start service first
.\erdps-agent.exe --agent-port 8080 --metrics-port 19091 &

# Then use scan-file command
.\erdps-agent.exe --scan-file test_file.txt
```

**Priority:** LOW - Workaround available, documentation issue

---

## Test Suite Analysis

### Overall Test Results

| Test Category | Passing | Failing | Pass Rate |
|---------------|---------|---------|-----------|
| Behavioral Performance | 2 | 0 | 100% |
| Memory Forensics | 2 | 0 | 100% |
| Network Performance | 3 | 0 | 100% |
| Performance Monitor | 5 | 0 | 100% |
| YARA Comprehensive | 7 | 0 | 100% |
| Comprehensive Agent | 6 | 0 | 100% |
| EMBER Response | 20 | 3 | 87% |
| Integration Tests | 0 | N/A | N/A (Compilation Error) |
| False Positive Tests | 0 | N/A | N/A (Compilation Error) |

### Test Coverage Analysis

**Strong Areas:**
- Core YARA functionality (100% pass rate)
- Performance monitoring (100% pass rate)
- Network performance (100% pass rate)
- Memory forensics (100% pass rate)

**Areas Needing Attention:**
- EMBER ML integration (87% pass rate)
- Integration testing (compilation issues)
- False positive validation (compilation issues)

---

## Remediation Roadmap

### Phase 1: Critical Issues (Week 1)
1. **Fix Dashboard Configuration**
   - Review and correct config.toml
   - Test dashboard startup
   - Validate web interface

2. **Resolve YARA Rule Issues**
   - Configure rule repositories
   - Fix validation process
   - Load production rule sets

3. **Establish Basic Detection**
   - Ensure rules are loaded
   - Validate scanning functionality
   - Test detection capabilities

### Phase 2: Medium Priority (Week 2-3)
1. **Stabilize EMBER Integration**
   - Fix failing ML tests
   - Validate feature extraction
   - Improve error handling

2. **Fix Test Framework**
   - Resolve compilation errors
   - Update async compatibility
   - Enable integration testing

3. **Validate False Positive Rates**
   - Fix test framework issues
   - Run comprehensive validation
   - Establish baseline metrics

### Phase 3: Low Priority (Week 4)
1. **Clean Up Warnings**
   - Fix file system monitoring
   - Improve error messages
   - Update documentation

2. **Optimize User Experience**
   - Improve CLI consistency
   - Add better error guidance
   - Enhance documentation

---

## Monitoring and Validation

### Post-Fix Validation Steps

1. **Critical Issue Validation:**
   ```bash
   # Test dashboard
   .\erdps-agent.exe --dashboard
   
   # Validate rules
   .\erdps-agent.exe validate-rules
   .\erdps-agent.exe stats
   
   # Test detection
   .\erdps-agent.exe scan-enhanced test_file.txt
   ```

2. **Test Suite Validation:**
   ```bash
   # Run all tests
   cargo test --all-features
   
   # Check pass rate
   cargo test --all-features 2>&1 | grep "test result:"
   ```

3. **Performance Validation:**
   ```bash
   # Check metrics
   curl http://127.0.0.1:19091/metrics
   
   # Performance test
   .\erdps-agent.exe show-metrics
   ```

### Success Criteria

- [ ] Dashboard starts successfully
- [ ] Rules load and validate properly
- [ ] Test pass rate >98%
- [ ] All critical functionality operational
- [ ] Performance within acceptable limits
- [ ] No critical errors in logs

---

## Contact and Escalation

**Primary Contact:** ERDPS Development Team  
**Escalation Path:** SOC Integration Team → Security Architecture Team  
**Documentation Updates:** Update this document after each fix implementation

---

*End of Known Issues Document*

**Document Version:** v0.1.0  
**Last Updated:** September 30, 2025  
**Next Review:** Upon completion of Phase 1 fixes