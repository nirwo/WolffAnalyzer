#!/usr/bin/env python3
"""Test script for improved log analyzer features"""

import os
import re
import json
import requests
from datetime import datetime
import time
import subprocess
import sys
import threading
import signal

# Configuration
PORT = 8082
HOST = "localhost"
SERVER_URL = f"http://{HOST}:{PORT}"
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs/sample_jenkins_build.log')
TIMEOUT = 30  # seconds to wait for server to start

def start_server():
    """Start the Flask server in a separate process"""
    server_process = subprocess.Popen(
        ["python", "app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    
    # Give the server time to start
    start_time = time.time()
    while time.time() - start_time < TIMEOUT:
        try:
            response = requests.get(f"{SERVER_URL}/")
            if response.status_code == 200:
                print(f"Server started successfully at {SERVER_URL}")
                return server_process
        except requests.RequestException:
            time.sleep(0.5)
    
    print("Failed to start server within timeout")
    server_process.terminate()
    sys.exit(1)

def stop_server(server_process):
    """Stop the Flask server"""
    if server_process:
        server_process.terminate()
        server_process.wait()
        print("Server stopped")

def test_analyze_endpoint():
    """Test the /test_analyze endpoint to verify improvements"""
    print("\n--- Testing log analysis with improved features ---")
    
    try:
        # Request the analysis page
        response = requests.get(f"{SERVER_URL}/test_analyze")
        if response.status_code != 200:
            print(f"Error: Failed to get analysis page, status code: {response.status_code}")
            return False
        
        html = response.text
        print("Successfully retrieved analysis page")
        
        # Check if patterns were matched
        pattern_matches = re.findall(r'data-pattern-id="(\d+)"', html)
        if not pattern_matches:
            print("No pattern matches found in the analysis")
            return False
        
        print(f"Found {len(pattern_matches)} pattern matches in the analysis")
        
        # Check for "Fix Pattern" buttons
        fix_pattern_buttons = re.findall(r'Fix Pattern</button>', html)
        print(f"Found {len(fix_pattern_buttons)} 'Fix Pattern' buttons")
        
        # Check for "Create Pattern from Log" buttons
        create_pattern_buttons = re.findall(r'Create Pattern from Log</button>', html)
        print(f"Found {len(create_pattern_buttons)} 'Create Pattern from Log' buttons")
        
        # Check for components that aren't paths or timestamps
        # This is basic - a real test would check the actual component values
        components = re.findall(r'<strong>Component:</strong> ([^<]+)</div>', html)
        path_components = 0
        timestamp_components = 0
        good_components = 0
        
        for component in components:
            if '/' in component or '\\' in component:
                path_components += 1
            elif re.match(r'\d{2}:\d{2}:\d{2}', component):
                timestamp_components += 1
            else:
                good_components += 1
        
        print(f"Component quality check:")
        print(f"- Good components: {good_components}")
        print(f"- Path components: {path_components}")
        print(f"- Timestamp components: {timestamp_components}")
        
        # Success criteria
        success = (
            len(pattern_matches) > 0 and
            len(fix_pattern_buttons) > 0 and
            len(create_pattern_buttons) > 0 and
            path_components == 0 and  # No paths should be identified as components
            timestamp_components == 0  # No timestamps should be identified as components
        )
        
        if success:
            print("\n✅ All improvements verified successfully!")
        else:
            print("\n❌ Some improvements failed verification")
        
        return success
    
    except Exception as e:
        print(f"Error testing analyze endpoint: {str(e)}")
        return False

def main():
    """Main test function"""
    server_process = None
    
    try:
        # Start the server
        server_process = start_server()
        
        # Run the tests
        test_analyze_endpoint()
    
    finally:
        # Stop the server
        if server_process:
            stop_server(server_process)

if __name__ == "__main__":
    main()