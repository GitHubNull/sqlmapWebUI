#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Preprocess script for Base64 encoded nested JSON parameters

Author: SQLMap Web UI Project
Date: 2026-03-27
Version: 1.0

Description:
    This preprocess script handles scenarios where:
    - The request body contains JSON with a 'content' field
    - The 'content' field is Base64 encoded
    - Inside the Base64 content is another JSON with injectable parameters
    
    Unlike tamper scripts, preprocess scripts can modify the entire request
    before it is sent to the target, including:
    - Modifying headers
    - Changing request method
    - Rewriting the entire request body
    - Handling complex encoding/decoding logic

Usage:
    Place this file in one of the following locations:
    1. SQLMap installation directory: /path/to/sqlmap/preprocess/
    2. Project directory: sqlmapWebUI/src/backEnd/preprocess/
    3. Current working directory
    
    Then run SQLMap:
    python sqlmap.py -u "http://target.com/api" \\
        --data='{"req_id":"1","content":"BASE64_ENCODED_DATA"}' \\
        --preprocess=preprocess_script.py \\
        -p content \\
        --batch

Difference from Tamper Scripts:
    - Tamper scripts: Modify only the injection payload
    - Preprocess scripts: Modify the entire request before sending

Configuration:
    Modify INNER_PARAM to match the actual parameter name in your API
    Modify OUTER_PARAM to match the encoded field name (default: "content")

Dependencies:
    - Standard library only (base64, json)
"""

import base64
import json

# ============================================================================
# CONFIGURATION - Modify these for your specific use case
# ============================================================================

INNER_PARAM = "name"      # The parameter inside the nested JSON to inject
OUTER_PARAM = "content"   # The outer field containing Base64 encoded data
INNER_DATA_TEMPLATE = {"age": 18}  # Additional static fields for inner JSON

# ============================================================================


def preprocess(req):
    """
    Preprocess the HTTP request before it is sent
    
    This function is called by SQLMap before each request is sent.
    It can modify any aspect of the request.
    
    Args:
        req: HTTPRequest object with attributes:
             - method: HTTP method (GET, POST, etc.)
             - url: Request URL
             - headers: Dictionary of headers
             - data: Request body (for POST/PUT requests)
             - cookies: Dictionary of cookies
    
    Returns:
        None (modifies req in place)
    """
    try:
        # Only process POST/PUT requests with body data
        if not req.data:
            return
        
        # Parse the outer JSON
        try:
            outer_data = json.loads(req.data)
        except json.JSONDecodeError:
            # Not JSON data, skip processing
            return
        
        # Check if the target field exists
        if OUTER_PARAM not in outer_data:
            return
        
        encoded_content = outer_data[OUTER_PARAM]
        
        # Try to decode existing content
        try:
            decoded_bytes = base64.b64decode(encoded_content)
            inner_json = decoded_bytes.decode('utf-8')
            inner_data = json.loads(inner_json)
        except Exception:
            # If decoding fails, create new inner data
            inner_data = INNER_DATA_TEMPLATE.copy()
        
        # Mark the injection point with a special marker
        # SQLMap will replace this marker with actual payloads
        if INNER_PARAM in inner_data:
            # Keep the original value but mark it for injection
            original_value = inner_data[INNER_PARAM]
            # SQLMap will detect this and replace it
            inner_data[INNER_PARAM] = original_value + "*"
        else:
            # Add the parameter with injection marker
            inner_data[INNER_PARAM] = "test*"
        
        # Re-encode the inner data
        new_inner_json = json.dumps(inner_data, ensure_ascii=False)
        new_encoded = base64.b64encode(new_inner_json.encode('utf-8')).decode('utf-8')
        
        # Update the request data
        outer_data[OUTER_PARAM] = new_encoded
        req.data = json.dumps(outer_data, ensure_ascii=False)
        
    except Exception as e:
        # Log error but don't break the request
        try:
            import sys
            sys.stderr.write(f"[preprocess error] {str(e)}\n")
        except:
            pass


def postprocess(resp):
    """
    Postprocess the HTTP response after it is received
    
    This function is called by SQLMap after each response is received.
    It can modify the response before SQLMap processes it.
    
    Args:
        resp: HTTPResponse object with attributes:
              - status: HTTP status code
              - reason: Status reason phrase
              - headers: Dictionary of headers
              - data: Response body
    
    Returns:
        None (modifies resp in place)
    """
    try:
        # If response is Base64 encoded, decode it for SQLMap
        if not resp.data:
            return
        
        # Try to parse as JSON
        try:
            response_data = json.loads(resp.data)
        except json.JSONDecodeError:
            return
        
        # Check if content field exists and is Base64
        if OUTER_PARAM not in response_data:
            return
        
        encoded_content = response_data[OUTER_PARAM]
        
        # Try to decode
        try:
            decoded_bytes = base64.b64decode(encoded_content)
            decoded_json = decoded_bytes.decode('utf-8')
            decoded_data = json.loads(decoded_json)
            
            # Replace the encoded content with decoded content
            # This helps SQLMap analyze the response
            response_data[OUTER_PARAM + "_decoded"] = decoded_data
            resp.data = json.dumps(response_data, ensure_ascii=False)
            
        except Exception:
            # Decoding failed, leave response as is
            pass
            
    except Exception as e:
        # Log error but don't break the response
        try:
            import sys
            sys.stderr.write(f"[postprocess error] {str(e)}\n")
        except:
            pass


# ============================================================================
# Testing code (only runs when script is executed directly)
# ============================================================================

if __name__ == "__main__":
    # Mock request object for testing
    class MockRequest:
        def __init__(self, data):
            self.method = "POST"
            self.url = "http://127.0.0.1:9527/api/encrypted/user/query"
            self.headers = {"Content-Type": "application/json"}
            self.data = data
            self.cookies = {}
    
    class MockResponse:
        def __init__(self, data):
            self.status = 200
            self.reason = "OK"
            self.headers = {"Content-Type": "application/json"}
            self.data = data
    
    print("=" * 60)
    print("Preprocess Script Test")
    print("=" * 60)
    
    # Test 1: Preprocess request
    print("\n[Test 1] Preprocess Request")
    print("-" * 40)
    
    original_data = json.dumps({
        "req_id": "123",
        "content": base64.b64encode(json.dumps({
            "name": "admin",
            "age": 18
        }).encode()).decode()
    })
    
    req = MockRequest(original_data)
    print(f"Before: {req.data}")
    preprocess(req)
    print(f"After:  {req.data}")
    
    # Verify
    try:
        outer = json.loads(req.data)
        inner = json.loads(base64.b64decode(outer["content"]).decode())
        print(f"Inner:  {inner}")
    except Exception as e:
        print(f"Verify error: {e}")
    
    # Test 2: Postprocess response
    print("\n[Test 2] Postprocess Response")
    print("-" * 40)
    
    response_data = json.dumps({
        "success": True,
        "content": base64.b64encode(json.dumps({
            "users": [{"id": 1, "name": "admin"}],
            "count": 1
        }).encode()).decode()
    })
    
    resp = MockResponse(response_data)
    print(f"Before: {resp.data}")
    postprocess(resp)
    print(f"After:  {resp.data}")
    
    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)
