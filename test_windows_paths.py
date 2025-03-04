#!/usr/bin/env python3
import re
from app import extract_component

# Test cases
test_cases = [
    # Windows paths that should NOT be identified as components
    "C:",
    "D:",
    "C:\\",
    "C:\\Windows",
    "C:\\Program Files\\App\\log.txt",
    "D:\\Data\\logs\\error.log",
    "Error in file C:\\Windows\\System32\\drivers\\etc\\hosts",
    "Reading from E:\\backup\\data.bak",
    
    # Valid component names that should be identified correctly
    "[2023-05-15T10:30:45.123Z] [INFO] [jenkins.main] Starting Jenkins",
    "[2025-03-03T03:03:41.029Z] [2;31m[2;1mgitw: Error: please make sure this are supported",
    "Dec 10 06:55:46 LabSZ sshd[24200]: message",
    "app.module.component: This is a log message",
    "system.service: Starting service",
    "[database.connection] Established connection to server"
]

print("Testing component extraction with Windows paths:")
print("-" * 50)

for test_case in test_cases:
    component = extract_component(test_case)
    is_windows_path = any(test_case.startswith(drive) for drive in ["C:", "D:", "E:"])
    
    print(f"Input: {test_case}")
    print(f"Extracted component: {component}")
    
    if is_windows_path and component != "Unknown":
        print("❌ FAILED: Windows path incorrectly identified as a component")
    elif not is_windows_path and component == "Unknown" and any(x in test_case for x in ["jenkins.main", "gitw", "sshd", "app.module.component", "system.service", "database.connection"]):
        print("❌ FAILED: Valid component not identified")
    else:
        print("✅ PASSED")
    
    print("-" * 50)
