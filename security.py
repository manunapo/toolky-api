import os

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader


API_KEY = os.getenv("API_KEY")

X_API_KEY = APIKeyHeader(name='X-API-Key')

def api_key_auth(api_key: str = Depends(X_API_KEY)):
    if API_KEY !=  api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Forbidden"
        )
