#!/usr/bin/env python3
import re
from app import extract_component

# Test cases for smart component extraction
test_cases = [
    # Single letters and short components that should be filtered out
    "Error in component A: Failed to connect",
    "B: Connection timeout",
    "Component C failed with error code 500",
    "ms: 150",
    "s: 2.5",
    "KB: 1024",
    "MB: 512",
    
    # Numeric-only components that should be filtered out
    "123: Error in processing",
    "Component 456: Failed to load",
    
    # Common words that should be filtered out
    "error: Connection refused",
    "warning: Disk space low",
    "the: system is down",
    "in: the middle of processing",
    
    # Valid components that should be identified correctly
    "[2023-05-15T10:30:45.123Z] [INFO] [jenkins.main] Starting Jenkins",
    "[2025-03-03T03:03:41.029Z] [2;31m[2;1mgitw: Error: please make sure this are supported",
    "Dec 10 06:55:46 LabSZ sshd[24200]: message",
    "app.module.component: This is a log message",
    "system.service: Starting service",
    "[database.connection] Established connection to server",
    
    # Components with common log prefixes
    "module myapp.core: Initializing",
    "component auth.service: Authentication failed",
    "service database.connector: Connection established",
    "class UserManager: User not found",
    "function processRequest: Invalid parameters",
    
    # Windows paths that should be filtered out
    "Error in file C:\\Windows\\System32\\drivers\\etc\\hosts",
    "Reading from E:\\backup\\data.bak",
    
    # Mixed cases that should be handled correctly
    "Error in component auth.service: Failed to authenticate user",
    "[2023-05-15T10:30:45.123Z] [ERROR] [jenkins.main] Error: C:\\ drive is full",
    "Dec 10 06:55:46 LabSZ sshd[24200]: Failed to read from /etc/ssh/sshd_config"
]

print("Testing smart component extraction:")
print("-" * 50)

for test_case in test_cases:
    component = extract_component(test_case)
    
    print(f"Input: {test_case}")
    print(f"Extracted component: {component}")
    print("-" * 50)
