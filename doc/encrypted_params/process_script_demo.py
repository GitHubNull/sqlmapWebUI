#!/usr/bin/env python

import json
from lib.core.data import logger
import base64

def preprocess(req):
    if req.data:
        # logger.info("Preprocess script: Modifying request body")
        # logger.debug("Original request data: %s" % req.data)
        # logger.debug("Original request data type: %s" % type(req.data))
        # # req.data += b'&foo=bar'
        pass
        try:
            outer_data = json.loads(req.data)
            logger.debug("Parsed outer JSON: %s" % outer_data)


            # Modify the outer JSON as needed
            before_data = outer_data['data']
            logger.debug("Original inner data (Base64): %s" % before_data)

             # 字符串需要先 encode 成 bytes，才能 b64encode
            after_data = base64.b64encode(before_data.encode('utf-8')).decode('utf-8')
            logger.debug("Encoded inner data (Base64): %s" % after_data)

            outer_data['data'] = after_data
            result = json.dumps(outer_data, ensure_ascii=False)
            logger.debug("result: %s" % result)

            # string to bytes
            req.data = result.encode('utf-8')
        except Exception as e:
            logger.error("Error in preprocess: %s" % str(e))
            pass

def postprocess(resp):
    if resp.data:
        # logger.info("Postprocess script: Modifying response body")
        # logger.debug("Original response data: %s" % resp.data)
        # logger.debug("Original response data type: %s" % type(resp.data))
        # resp.data += b'\n<!-- Modified by postprocess script -->'
        pass
        try:
            response_data = json.loads(resp.data)
            logger.debug("Parsed response JSON: %s" % response_data)
            if 'data' in response_data:
                before_data = response_data['data']
                logger.debug("Original inner data base64 encoded: %s" % before_data)


                after_data = base64.b64decode(before_data.encode('utf-8')).decode('utf-8')
                logger.debug("base64 decoded data: %s" % after_data)


                response_data['data'] = after_data
                result = json.dumps(response_data, ensure_ascii=False)
                logger.debug("Re-encoded response JSON: %s" % result)

                # string to bytes
                resp.data = result.encode('utf-8')
        except Exception as e:
            logger.error("Error in postprocess: %s" % str(e))
            pass