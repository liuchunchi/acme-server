from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.acme_errors import (
    AccountDoesNotExistError,
    AlreadyRevokedError,
    MalformedError,
    UnauthorizedError,
)
from app.crypto import verify_jws
from app.storage import get_storage

router = APIRouter()


@router.post("/acme/cert/{cert_id}")
async def get_certificate(cert_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()
    kid = protected.get("kid")
    if not kid:
        raise UnauthorizedError()
    account = storage.get_account_by_url(kid)
    if not account:
        raise AccountDoesNotExistError()

    cert = storage.get_certificate(cert_id)
    if not cert:
        raise MalformedError("Certificate not found")

    if cert.account_id != account.id:
        raise UnauthorizedError()

    if cert.revoked:
        raise AlreadyRevokedError()

    return Response(
        content=cert.chain_pem,
        media_type="application/pem-certificate-chain",
        headers={"Content-Disposition": f'attachment; filename="cert_{cert_id}.pem"'},
    )


@router.post("/acme/revoke-cert")
async def revoke_certificate(request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()

    cert_b64 = payload.get("certificate")
    if not cert_b64:
        raise MalformedError("Missing certificate")

    from app.crypto import b64url_decode
    try:
        cert_der = b64url_decode(cert_b64)
    except Exception:
        raise MalformedError("Invalid certificate encoding")

    from cryptography import x509
    try:
        cert_obj = x509.load_der_x509_certificate(cert_der)
    except Exception:
        raise MalformedError("Invalid certificate")

    # Find the certificate in storage by comparing
    cert_pem = cert_obj.public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM
    ).decode("ascii")

    found_cert = None
    for c in storage._certificates.values():
        if c.cert_pem.strip() == cert_pem.strip() or c.chain_pem.strip().startswith(cert_pem.strip()):
            found_cert = c
            break

    if not found_cert:
        raise MalformedError("Certificate not found")

    if found_cert.revoked:
        raise AlreadyRevokedError()

    # Verify ownership: either the account owns it, or the request JWK matches the cert key
    kid = protected.get("kid")
    jwk = protected.get("jwk")

    if kid:
        account = storage.get_account_by_url(kid)
        if not account:
            raise AccountDoesNotExistError()
        if found_cert.account_id != account.id:
            raise UnauthorizedError()
    elif jwk:
        # Check if JWK matches the certificate's public key
        from app.crypto import _jwk_to_public_key
        try:
            jwk_key = _jwk_to_public_key(jwk)
            cert_key = cert_obj.public_key()
            if jwk_key.public_numbers() != cert_key.public_numbers():
                raise UnauthorizedError()
        except UnauthorizedError:
            raise
        except Exception:
            raise UnauthorizedError()
    else:
        raise UnauthorizedError()

    storage._certificates[found_cert.id].revoked = True

    return Response(status_code=200)
