from fastapi import HTTPException, Request, status
from typing import Optional


def get_current_user(request: Request, token: Optional[str] = None):
    if request.client is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client information not available",
        )

    client_ip = request.client.host
    if client_ip in ["127.0.0.1", "localhost"]:
        return {"user": "admin"}

    if token != "secret-token":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"user": "authenticated"}
