#!/usr/bin/env python3
"""Verify pattern matching in log analyzer"""

import os
import json
from app import parse_log, analyze_log_entries, enhanced_extract_component

def verify_pattern_match():
    """Test pattern matching with the sample log file"""
    print("=== Verifying Pattern Matching Improvements ===")
    
    # Read sample log file
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs/sample_jenkins_build.log')
    with open(log_path, 'r', encoding='utf-8') as f:
        log_content = f.read()
    
    # Parse the log
    entries = parse_log(log_content)
    print(f"Parsed {len(entries)} log entries")
    
    # Load the patterns
    patterns_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'patterns.json')
    with open(patterns_path, 'r') as f:
        patterns = json.load(f)
    
    print(f"Loaded {len(patterns['jenkins_patterns'])} Jenkins patterns and {len(patterns['system_patterns'])} system patterns")
    
    # Check component extraction quality
    component_counts = {}
    for entry in entries:
        component = entry.get('component', 'None')
        component_counts[component] = component_counts.get(component, 0) + 1
    
    print("\nComponent extraction results:")
    for component, count in sorted(component_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"- {component}: {count} entries")
    
    # Test pattern matching
    analysis = analyze_log_entries(entries)
    print(f"\nFound {len(analysis.get('pattern_matches', []))} pattern matches")
    
    # Count matches by pattern
    pattern_match_counts = {}
    for match in analysis.get('pattern_matches', []):
        pattern_name = match.get('pattern_name', 'Unknown')
        pattern_match_counts[pattern_name] = pattern_match_counts.get(pattern_name, 0) + 1
    
    print("\nPattern match distribution:")
    for pattern, count in sorted(pattern_match_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"- {pattern}: {count} matches")
    
    # Check for false positives in components (paths or timestamps)
    path_components = [e for e in entries if e.get('component') and ('/' in e.get('component') or '\\' in e.get('component'))]
    timestamp_components = [e for e in entries if e.get('component') and ':' in e.get('component') and e.get('component')[0].isdigit()]
    
    print(f"\nFalse positives check:")
    print(f"- Path components: {len(path_components)}")
    print(f"- Timestamp components: {len(timestamp_components)}")
    
    # Manual pattern testing
    print("\nTesting enhanced component extraction:")
    test_lines = [
        "[2025-03-04T09:14:50.567Z] Module not found: Error: Can't resolve './ChartComponent'",
        "npm ERR! code ELIFECYCLE",
        "C:\\Windows\\System32\\node_modules\\webpack\\bin\\webpack.js:308 threw an error",
        "/usr/lib/node_modules/webpack/bin/webpack.js:308: Command failed with exit code 1",
        "12:45:32 ERROR Failed to connect to database",
        "500 MB memory usage, 87.3% CPU during compilation"
    ]
    
    for line in test_lines:
        component = enhanced_extract_component(line)
        print(f"Line: {line[:40]}...")
        print(f"Component: {component}")
    
    print("\n=== Verification complete ===")

if __name__ == "__main__":
    verify_pattern_match()