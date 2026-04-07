#!/usr/bin/env python3
"""
YARA Rules Pre-compilation Validation Script
Part of ERDPS Agent remediation plan

This script validates YARA rules before compilation to prevent runtime errors.
"""

import os
import sys
import glob
import subprocess
from pathlib import Path

# Fix Windows CP1252 console encoding issues
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

def validate_yara_rules(rules_directory):
    """
    Validate all YARA rules in the specified directory
    Returns: (success: bool, errors: list)
    """
    errors = []
    success = True
    
    # Find all .yar and .yara files
    yar_files = glob.glob(os.path.join(rules_directory, "*.yar"))
    yara_files = glob.glob(os.path.join(rules_directory, "*.yara"))
    all_rule_files = yar_files + yara_files
    
    if not all_rule_files:
        errors.append(f"No .yar or .yara files found in {rules_directory}")
        return False, errors
    
    print(f"Validating {len(all_rule_files)} YARA rule files...")
    
    for yar_file in all_rule_files:
        print(f"Checking: {os.path.basename(yar_file)}")
        
        # Check file exists and is readable
        if not os.path.isfile(yar_file):
            errors.append(f"File not found: {yar_file}")
            success = False
            continue
            
        # Check file is not empty
        if os.path.getsize(yar_file) == 0:
            errors.append(f"Empty file: {yar_file}")
            success = False
            continue
            
        # Basic syntax validation
        try:
            with open(yar_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Check for basic YARA structure
            if 'rule ' not in content:
                errors.append(f"No rules found in: {yar_file}")
                success = False
                continue
                
            # Check for balanced braces (excluding braces in strings)
            in_string = False
            escape_next = False
            open_braces = 0
            close_braces = 0
            
            for i, char in enumerate(content):
                if escape_next:
                    escape_next = False
                    continue
                    
                if char == '\\' and in_string:
                    escape_next = True
                    continue
                    
                if char == '"' and not escape_next:
                    in_string = not in_string
                    continue
                    
                if not in_string:
                    if char == '{':
                        open_braces += 1
                    elif char == '}':
                        close_braces += 1
            
            if open_braces != close_braces:
                errors.append(f"Unbalanced braces in: {yar_file} (open: {open_braces}, close: {close_braces})")
                success = False
                continue
                
            print(f"  [OK] Basic syntax validation passed")
            
        except Exception as e:
            errors.append(f"Error reading {yar_file}: {str(e)}")
            success = False
            continue
    
    # Check for duplicate rule names across files
    rule_names = {}
    for yar_file in all_rule_files:
        try:
            with open(yar_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Extract rule names (improved approach)
            lines = content.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                if line.startswith('rule '):
                    # Handle both "rule name {" and "rule name\n{" formats
                    if '{' in line:
                        rule_name = line.split()[1].split('{')[0].strip()
                    else:
                        # Rule name is on this line, brace on next line
                        parts = line.split()
                        if len(parts) >= 2:
                            rule_name = parts[1].strip()
                        else:
                            continue
                    
                    if rule_name in rule_names:
                        errors.append(f"Duplicate rule '{rule_name}' found in {yar_file} and {rule_names[rule_name]}")
                        success = False
                    else:
                        rule_names[rule_name] = yar_file
                        
        except Exception as e:
            errors.append(f"Error checking duplicates in {yar_file}: {str(e)}")
            success = False
    
    if success:
        print(f"[OK] All {len(all_rule_files)} YARA rule files passed validation")
        print(f"[OK] Found {len(rule_names)} unique rules")
    else:
        print(f"[FAIL] Validation failed with {len(errors)} errors")
    
    return success, errors

def main():
    if len(sys.argv) != 2:
        print("Usage: python validate_yara_rules.py <rules_directory>")
        sys.exit(1)
        
    rules_dir = sys.argv[1]
    
    if not os.path.isdir(rules_dir):
        print(f"Error: Directory not found: {rules_dir}")
        sys.exit(1)
    
    success, errors = validate_yara_rules(rules_dir)
    
    if errors:
        print("\nValidation Errors:")
        for error in errors:
            print(f"  - {error}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()