#!/usr/bin/env python
"""
Preprocess script for Base64 encoded nested JSON parameters

Author: SQLMap Web UI Project
Date: 2026-03-27
Version: 1.1

Description:
    This preprocess script handles scenarios where:
    - The request body contains JSON with a 'data' field
    - The 'data' field value is a plain string that needs to be Base64 encoded
    - The encoded result replaces the original field value before sending
    - The response 'data' field is Base64 encoded and needs to be decoded

    Target interface: POST /api/coupon/query  (VulnShop coupon endpoints)
    Request structure:
        {"req_id": "123", "data": "<plain_inner_json_string>"}
    After preprocess:
        {"req_id": "123", "data": "<base64_encoded_inner_json_string>"}

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
    python sqlmap.py -u "http://127.0.0.1:9527/api/coupon/query" \\
        --data='{"req_id":"1","data":"{\\"coupon_code\\":\\"SAVE10\\"}"}' \\
        --preprocess=preprocess_script.py \\
        -p data \\
        --batch

Difference from Tamper Scripts:
    - Tamper scripts: Modify only the injection payload
    - Preprocess scripts: Modify the entire request before sending

Configuration:
    Modify OUTER_PARAM to match the encoded field name (default: "data")

Dependencies:
    - Standard library only (base64, json)
    - SQLMap built-in: lib.core.data.logger
"""

import json
from lib.core.data import logger
import base64

# ============================================================================
# CONFIGURATION - Modify these for your specific use case
# ============================================================================

OUTER_PARAM = "data"   # The outer field whose string value needs Base64 encoding

# ============================================================================


def preprocess(req):
    """
    Preprocess the HTTP request before it is sent.

    Encodes the value of OUTER_PARAM field with Base64 before sending.
    SQLMap places its payload into the field as a plain string;
    this function encodes it so the server receives a Base64-encoded value.

    Args:
        req: HTTPRequest object with attributes:
             - method: HTTP method (GET, POST, etc.)
             - url: Request URL
             - headers: Dictionary of headers
             - data: Request body bytes (for POST/PUT requests)
             - cookies: Dictionary of cookies

    Returns:
        None (modifies req in place)
    """
    if req.data:
        pass
        try:
            outer_data = json.loads(req.data)
            logger.debug("Parsed outer JSON: %s" % outer_data)

            # Read the plain string value that SQLMap has injected into
            before_data = outer_data[OUTER_PARAM]
            logger.debug("Original inner data (plain string): %s" % before_data)

            # Encode the string to Base64 (string -> bytes -> b64encode -> string)
            after_data = base64.b64encode(before_data.encode('utf-8')).decode('utf-8')
            logger.debug("Encoded inner data (Base64): %s" % after_data)

            outer_data[OUTER_PARAM] = after_data
            result = json.dumps(outer_data, ensure_ascii=False)
            logger.debug("result: %s" % result)

            # string to bytes
            req.data = result.encode('utf-8')
        except Exception as e:
            logger.error("Error in preprocess: %s" % str(e))
            pass


def postprocess(resp):
    """
    Postprocess the HTTP response after it is received.

    Decodes the Base64-encoded value of OUTER_PARAM in the response so that
    SQLMap can read the plain-text content for injection analysis.

    Args:
        resp: HTTPResponse object with attributes:
              - status: HTTP status code
              - reason: Status reason phrase
              - headers: Dictionary of headers
              - data: Response body bytes

    Returns:
        None (modifies resp in place)
    """
    if resp.data:
        pass
        try:
            response_data = json.loads(resp.data)
            logger.debug("Parsed response JSON: %s" % response_data)
            if OUTER_PARAM in response_data:
                before_data = response_data[OUTER_PARAM]
                logger.debug("Original inner data base64 encoded: %s" % before_data)

                after_data = base64.b64decode(before_data.encode('utf-8')).decode('utf-8')
                logger.debug("base64 decoded data: %s" % after_data)

                response_data[OUTER_PARAM] = after_data
                result = json.dumps(response_data, ensure_ascii=False)
                logger.debug("Re-encoded response JSON: %s" % result)

                # string to bytes
                resp.data = result.encode('utf-8')
        except Exception as e:
            logger.error("Error in postprocess: %s" % str(e))
            pass


# ============================================================================
# Testing code (only runs when script is executed directly)
# ============================================================================

if __name__ == "__main__":
    # Mock logger for standalone testing (replaces lib.core.data.logger)
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("preprocess_test")

    # Mock request object for testing
    class MockRequest:
        def __init__(self, data):
            self.method = "POST"
            self.url = "http://127.0.0.1:9527/api/coupon/query"
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
    # SQLMap injects its payload as the plain string value of 'data';
    # preprocess encodes it to Base64 before sending to the server.
    print("\n[Test 1] Preprocess Request")
    print("-" * 40)

    original_data = json.dumps({
        "req_id": "123",
        "data": '{"coupon_code": "SAVE10"}'
    })

    req = MockRequest(original_data.encode('utf-8'))
    print("Before: %s" % req.data)
    preprocess(req)
    print("After:  %s" % req.data)

    # Verify: decode the Base64 value back to the original string
    try:
        outer = json.loads(req.data)
        decoded_inner = base64.b64decode(outer["data"]).decode('utf-8')
        print("Decoded inner: %s" % decoded_inner)
    except Exception as e:
        print("Verify error: %s" % e)

    # Test 2: Postprocess response
    # Server returns response with 'data' field Base64-encoded;
    # postprocess decodes it so SQLMap can analyse the plain-text content.
    print("\n[Test 2] Postprocess Response")
    print("-" * 40)

    inner_response = json.dumps({
        "coupons": [{"id": 1, "coupon_code": "SAVE10"}],
        "count": 1
    })
    response_body = json.dumps({
        "success": True,
        "req_id": "123",
        "data": base64.b64encode(inner_response.encode('utf-8')).decode('utf-8')
    })

    resp = MockResponse(response_body.encode('utf-8'))
    print("Before: %s" % resp.data)
    postprocess(resp)
    print("After:  %s" % resp.data)

    print("\n" + "=" * 60)
    print("Test completed!")
    print("=" * 60)
