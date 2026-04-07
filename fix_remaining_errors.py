#!/usr/bin/env python3
"""
Script to fix remaining AgentError::Service context field errors
"""
import os
import re
import glob

def fix_agent_error_context_fields():
    """Fix all AgentError::Service context field syntax errors"""
    
    # Pattern to match AgentError::Service with missing comma before context
    pattern = r'(AgentError::Service\s*\{\s*[^}]*service:\s*[^,}]*)\s*context:\s*None\s*\}'
    replacement = r'\1,\n                    context: None\n                }'
    
    # Find all Rust files in src directory
    rust_files = []
    for root, dirs, files in os.walk('src'):
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))
    
    fixed_files = []
    
    for file_path in rust_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if file contains the problematic pattern
            if 'AgentError::Service' in content and 'context: None' in content:
                # Fix the pattern
                new_content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
                
                # Also fix cases where there's a duplicate context field
                new_content = re.sub(r'context:\s*None,\s*context:\s*None', 'context: None', new_content)
                
                # Fix missing commas in general
                new_content = re.sub(
                    r'(service:\s*[^,}]*)\s*context:\s*None',
                    r'\1,\n                    context: None',
                    new_content
                )
                
                if new_content != content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    fixed_files.append(file_path)
                    print(f"Fixed: {file_path}")
        
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    print(f"\nFixed {len(fixed_files)} files:")
    for file in fixed_files:
        print(f"  - {file}")

if __name__ == "__main__":
    fix_agent_error_context_fields()