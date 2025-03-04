#!/usr/bin/env python3
import sys
import re
from app import extract_component, parse_log

# Test files
jenkins_log = 'jenkins_example.log'
openssh_log = 'openssh_example.log'
jenkins_ansi_log = 'jenkins_ansi_example.log'

def test_component_extraction():
    print("Testing component extraction...")
    
    # Test Jenkins log format
    with open(jenkins_log, 'r') as f:
        jenkins_lines = f.readlines()
    
    for line in jenkins_lines:
        component = extract_component(line.strip())
        print(f"Line: {line.strip()}")
        print(f"Extracted component: {component}")
        print("-" * 50)
    
    # Test OpenSSH log format
    with open(openssh_log, 'r') as f:
        ssh_lines = f.readlines()
    
    for line in ssh_lines:
        component = extract_component(line.strip())
        print(f"Line: {line.strip()}")
        print(f"Extracted component: {component}")
        print("-" * 50)
        
    # Test Jenkins ANSI color code format
    print("\nTesting Jenkins ANSI color code format...")
    with open(jenkins_ansi_log, 'r') as f:
        jenkins_ansi_lines = f.readlines()
    
    for line in jenkins_ansi_lines:
        component = extract_component(line.strip())
        print(f"Line: {line.strip()}")
        print(f"Extracted component: {component}")
        print("-" * 50)

def test_log_parsing():
    print("\nTesting full log parsing...")
    
    # Test Jenkins log format
    with open(jenkins_log, 'r') as f:
        jenkins_content = f.read()
    
    jenkins_entries = parse_log(jenkins_content)
    print(f"Jenkins log entries: {len(jenkins_entries)}")
    for entry in jenkins_entries:
        print(f"Timestamp: {entry.get('timestamp', 'None')}")
        print(f"Component: {entry.get('component', 'Unknown')}")
        print(f"Error Level: {entry.get('level', 'Unknown')}")
        print(f"Message: {entry.get('message', '')}")
        print("-" * 50)
    
    # Test OpenSSH log format
    with open(openssh_log, 'r') as f:
        ssh_content = f.read()
    
    ssh_entries = parse_log(ssh_content)
    print(f"OpenSSH log entries: {len(ssh_entries)}")
    for entry in ssh_entries:
        print(f"Timestamp: {entry.get('timestamp', 'None')}")
        print(f"Component: {entry.get('component', 'Unknown')}")
        print(f"Error Level: {entry.get('level', 'Unknown')}")
        print(f"Message: {entry.get('message', '')}")
        print("-" * 50)
        
    # Test Jenkins ANSI color code format
    with open(jenkins_ansi_log, 'r') as f:
        jenkins_ansi_content = f.read()
    
    jenkins_ansi_entries = parse_log(jenkins_ansi_content)
    print(f"Jenkins ANSI log entries: {len(jenkins_ansi_entries)}")
    for entry in jenkins_ansi_entries:
        print(f"Timestamp: {entry.get('timestamp', 'None')}")
        print(f"Component: {entry.get('component', 'Unknown')}")
        print(f"Error Level: {entry.get('level', 'Unknown')}")
        print(f"Message: {entry.get('message', '')}")
        print("-" * 50)

if __name__ == "__main__":
    test_component_extraction()
    test_log_parsing()
