from fastapi import status
from fastapi.responses import JSONResponse


class BaseResponseMsg(JSONResponse):
    def __init__(self, data=None, msg="", success=False, code=status.HTTP_200_OK):
        super().__init__(
            content={
                "code": code,
                "success": success,
                "message": msg,
                "data": data,
            },
            status_code=status.HTTP_200_OK
        )
