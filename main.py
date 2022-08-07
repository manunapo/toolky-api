import secrets, string, base64
from fastapi import FastAPI, Depends, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from logging.config import dictConfig
import logging
from logConfig import log_config

from security import api_key_auth

dictConfig(log_config)

app = FastAPI(debug=True, title="Password Generator", description="A simple API for generating passwords. You can specify the length, and if it would contain lowercases, uppercases, special characters and or digits.")

origins = [
    "http://localhost:3000",
    "localhost:3000"
]

logger = logging.getLogger('foo-logger')

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"]
)

class GeneratedPassword(BaseModel):
    newpass: str
    
class EncodedString(BaseModel):
    value: str
    charset: str
    
class DecodedString(BaseModel):
    value: str
    charset: str

@app.post("/base64/enc/", tags=["Base64"], response_model=EncodedString, status_code=200, dependencies=[Depends(api_key_auth)])
async def encode_base64( input: DecodedString) -> EncodedString:
    logger.debug(f"Input to encode: {input}")
    #encoded = base64.b64encode( input.value.encode( input.charset))
    encoded = base64.b64encode( input.value.encode( "ascii"))
    logger.debug(f"Encoded value: {encoded}")
    return {"value": encoded, "charset": input.charset}

@app.post("/base64/dec/", tags=["Base64"], response_model=DecodedString, status_code=200, dependencies=[Depends(api_key_auth)])
async def decode_base64( input: EncodedString) -> DecodedString:
    logger.debug(f"Input to decode: {input}")
    #decoded = base64.b64decode( input.value).decode( input.charset)
    decoded = base64.b64decode( input.value)
    logger.debug(f"Decoded value: {decoded}")
    return {"value": decoded, "charset": input.charset}

@app.get("/newpass/", tags=["Generator"], response_model=GeneratedPassword, status_code=200, dependencies=[Depends(api_key_auth)])
async def generate_password( length: int = 8, uppercases: bool = True, lowercases: bool = True, digits: bool = True, specials: bool = False) -> dict:
    alphabet = []
    if uppercases:
        alphabet.extend( string.ascii_uppercase)
    if lowercases:
        alphabet.extend( string.ascii_lowercase)
    if digits:
        alphabet.extend( string.digits)
    if specials:
        alphabet.extend( string.punctuation)
    if not alphabet:
        alphabet = string.ascii_lowercase
    password = ''.join(secrets.choice(alphabet) for _ in range( length))
    return {"newpass": password}

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=exc.errors()[0],
    )