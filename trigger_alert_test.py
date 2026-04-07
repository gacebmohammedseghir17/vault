#!/usr/bin/env python3
"""
Simple script to trigger mass modification alerts by creating many files quickly
"""

import os
import time
import tempfile

def trigger_mass_modification():
    """Create many files quickly to trigger mass modification detection"""
    # Create a temporary directory for our test
    test_dir = os.path.join(tempfile.gettempdir(), "erdps_alert_test")
    os.makedirs(test_dir, exist_ok=True)
    
    print(f"Creating test files in: {test_dir}")
    
    # Create 60 files quickly (above the 50 threshold)
    for i in range(60):
        file_path = os.path.join(test_dir, f"test_file_{i:03d}.txt")
        with open(file_path, 'w') as f:
            f.write(f"Test file {i} - created to trigger mass modification alert\n")
        
        if i % 10 == 0:
            print(f"Created {i+1} files...")
    
    print(f"✓ Created 60 files in {test_dir}")
    print("This should trigger a mass_modification alert!")
    
    # Wait a moment then clean up
    time.sleep(2)
    
    print("Cleaning up test files...")
    for i in range(60):
        file_path = os.path.join(test_dir, f"test_file_{i:03d}.txt")
        try:
            os.remove(file_path)
        except FileNotFoundError:
            pass
    
    try:
        os.rmdir(test_dir)
        print("✓ Cleanup completed")
    except OSError:
        print("⚠️  Directory not empty, some files may remain")

if __name__ == "__main__":
    print("🚨 ERDPS Alert Trigger Test")
    print("This will create 60 files quickly to trigger mass modification detection")
    trigger_mass_modification()