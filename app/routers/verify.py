from fastapi import APIRouter, Request, Response

from app.storage import get_storage
from app.acme_errors import (
    BadVerifyError,
)
import logging
logger = logging.getLogger("acme.verify")

from cryptography.hazmat.primitives import serialization
from app.crypto import b64url_encode

router = APIRouter()


@router.get("/acme/verify/{verify_id}")
async def verify_id(verify_id: str, request: Request):
    logger.info(f"verify id: {verify_id}")
    storage = get_storage();
    logger.info(f"storage")
    private_key = storage.get_rsa_private(verify_id)
    logger.info(f"private key: {private_key}")
    if private_key is None:
        raise BadVerifyError()
    public_key = private_key.public_key()
    logger.info(f"public key: {public_key}")
    pem_pub_key = public_key.public_bytes( encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo )
    logger.info(f"pem pub key: {pem_pub_key}")
    return  {"verify_key":pem_pub_key}
    