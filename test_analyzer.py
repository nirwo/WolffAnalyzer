#!/usr/bin/env python3
"""Test script for log analyzer improvements"""

import os
import json
from app import parse_log, analyze_log_entries, generate_recommendations, enhanced_extract_component

def test_log_analyzer():
    """Test the log analyzer with a sample Jenkins log file"""
    print("Testing log analyzer with sample Jenkins build log...")
    
    # Read the sample log file
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs/sample_jenkins_build.log')
    with open(log_path, 'r', encoding='utf-8') as f:
        log_content = f.read()
    
    # Parse the log
    print("\n1. Testing log parsing...")
    entries = parse_log(log_content)
    print(f"Parsed {len(entries)} log entries")
    
    # Check component extraction
    print("\n2. Testing component extraction...")
    components = set()
    path_components = []
    timestamp_components = []
    
    for entry in entries:
        if entry['component']:
            components.add(entry['component'])
            
            # Check for false positives (paths or timestamps as components)
            if '/' in entry['component'] or '\\' in entry['component']:
                path_components.append(entry)
            elif ':' in entry['component'] and entry['component'][0].isdigit():
                timestamp_components.append(entry)
    
    print(f"Found {len(components)} unique components: {', '.join(components)}")
    
    if path_components:
        print(f"WARNING: Found {len(path_components)} entries with paths as components")
        for entry in path_components[:3]:
            print(f" - {entry['component']} in: {entry['message'][:50]}...")
    else:
        print("SUCCESS: No paths detected as components")
    
    if timestamp_components:
        print(f"WARNING: Found {len(timestamp_components)} entries with timestamps as components")
        for entry in timestamp_components[:3]:
            print(f" - {entry['component']} in: {entry['message'][:50]}...")
    else:
        print("SUCCESS: No timestamps detected as components")
    
    # Analyze the log
    print("\n3. Testing log analysis...")
    analysis = analyze_log_entries(entries)
    
    print(f"Critical issues: {analysis.get('critical_issues_count', 0)}")
    print(f"Pattern matches: {len(analysis.get('pattern_matches', []))}")
    
    # Print pattern matches
    if analysis.get('pattern_matches'):
        print("\nPattern matches:")
        for i, match in enumerate(analysis['pattern_matches'][:5]):
            print(f"{i+1}. {match['pattern_name']} ({match['severity']}): {match['matched_line'][:50]}...")
    
    # Generate recommendations
    print("\n4. Testing recommendation generation...")
    recommendations = generate_recommendations(entries, analysis)
    
    print(f"Generated {len(recommendations)} recommendations")
    for i, rec in enumerate(recommendations[:3]):
        print(f"{i+1}. {rec['title']}")
        print(f"   Description: {rec['description'][:50]}...")
    
    # Test the enhanced component extraction
    print("\n5. Testing enhanced component extraction...")
    test_cases = [
        "2025-03-04T09:14:50.567Z Module not found: Error",
        "C:\\Windows\\System32\\node_modules\\webpack\\bin\\webpack.js:308 threw an error",
        "/usr/lib/node_modules/webpack/bin/webpack.js:308: Command failed",
        "Dashboard component dependencies missing",
        "12:45:32 ERROR Failed to connect",
        "500 MB memory used during build",
        "Process exited with status 1"
    ]
    
    for test in test_cases:
        orig_component = enhanced_extract_component(test)
        print(f"Message: {test}")
        print(f"Component: {orig_component}")
        print()
    
    print("Log analyzer test completed!")

if __name__ == "__main__":
    test_log_analyzer()