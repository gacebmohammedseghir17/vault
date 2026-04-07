#!/usr/bin/env python3
"""
Script to fix AgentError::Service compilation errors
"""

import os
import re
import glob

def fix_agent_error_service(content):
    """Fix malformed AgentError::Service instances"""
    
    # Fix malformed format strings with {, context: None }
    content = re.sub(
        r'\{, context: None \}',
        '{}',
        content
    )
    
    # Fix missing context field in AgentError::Service
    # Pattern: AgentError::Service { message: ..., service: ... }
    # Should be: AgentError::Service { message: ..., service: ..., context: None }
    
    # First, fix cases where context is missing entirely
    pattern = r'(AgentError::Service\s*\{\s*message:\s*[^}]+,\s*service:\s*[^}]+)\s*\}'
    replacement = r'\1, context: None }'
    
    # Only replace if context is not already present
    def replace_if_no_context(match):
        full_match = match.group(0)
        if 'context:' not in full_match:
            return match.group(1) + ', context: None }'
        return full_match
    
    content = re.sub(pattern, replace_if_no_context, content)
    
    # Fix malformed context field placement
    content = re.sub(
        r'(AgentError::Service\s*\{\s*message:\s*[^}]+,\s*service:\s*[^}]+)\s*,\s*context:\s*None\s*\}\s*,\s*context:\s*None\s*\}',
        r'\1, context: None }',
        content
    )
    
    return content

def fix_file(filepath):
    """Fix a single file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        content = fix_agent_error_service(content)
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed: {filepath}")
            return True
        else:
            print(f"No changes needed: {filepath}")
            return False
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def main():
    """Main function"""
    base_dir = r"d:\projecttttttttts\project-ransolution\agent\src"
    
    # Find all Rust files
    rust_files = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))
    
    print(f"Found {len(rust_files)} Rust files")
    
    fixed_count = 0
    for filepath in rust_files:
        if fix_file(filepath):
            fixed_count += 1
    
    print(f"Fixed {fixed_count} files")

if __name__ == "__main__":
    main()