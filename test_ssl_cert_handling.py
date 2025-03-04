#!/usr/bin/env python3
"""
Test the SSL certificate handling functionality for log analyzer
This script tests various SSL certificate configurations with the requests library
to ensure our approach correctly handles certificate issues
"""

import os
import sys
import requests
import ssl
import certifi
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_ssl_cert_options():
    """Test different SSL certificate options for making requests"""
    print("=== Testing SSL Certificate Handling ===")
    
    # 1. Test with default system certificates
    test_url = "https://www.google.com"
    print(f"\n1. Testing with default system certificates: {test_url}")
    try:
        response = requests.get(test_url, timeout=10)
        print(f"  ✅ Success: Status code {response.status_code}")
    except requests.exceptions.SSLError as e:
        print(f"  ❌ SSL Error: {str(e)}")
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # 2. Test with certifi certificates
    print(f"\n2. Testing with certifi certificates: {test_url}")
    try:
        cert_path = certifi.where()
        print(f"  Using certifi path: {cert_path}")
        response = requests.get(test_url, timeout=10, verify=cert_path)
        print(f"  ✅ Success: Status code {response.status_code}")
    except requests.exceptions.SSLError as e:
        print(f"  ❌ SSL Error: {str(e)}")
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # 3. Test with SSL verification disabled
    print(f"\n3. Testing with SSL verification disabled: {test_url}")
    try:
        response = requests.get(test_url, timeout=10, verify=False)
        print(f"  ✅ Success: Status code {response.status_code}")
        print("  ⚠️ Warning: SSL verification was disabled")
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    # 4. Print system certificate information
    print("\n4. System certificate information:")
    try:
        default_verify = ssl.get_default_verify_paths()
        print(f"  Default cafile: {default_verify.cafile}")
        print(f"  Default capath: {default_verify.capath}")
        print(f"  Default openssl cafile: {default_verify.openssl_cafile}")
        print(f"  Default openssl capath: {default_verify.openssl_capath}")
        
        print(f"\n  Certifi cafile: {certifi.where()}")
        
        # Check if paths exist
        if default_verify.cafile and os.path.exists(default_verify.cafile):
            print(f"  ✅ System cafile exists")
        else:
            print(f"  ❌ System cafile does not exist or is not set")
            
        if certifi.where() and os.path.exists(certifi.where()):
            print(f"  ✅ Certifi cafile exists")
        else:
            print(f"  ❌ Certifi cafile does not exist")
    except Exception as e:
        print(f"  ❌ Error getting certificate information: {str(e)}")
    
    print("\n=== SSL Certificate Handling Test Complete ===")

if __name__ == "__main__":
    test_ssl_cert_options()