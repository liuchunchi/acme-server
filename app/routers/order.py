from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.acme_errors import (
    AccountDoesNotExistError,
    MalformedError,
    OrderNotReadyError,
    UnauthorizedError,
    BadCsrError,
)
from app.config import settings
from app.crypto import verify_jws, sign_csr, ensure_ca, validate_csr_identifiers, b64url_decode
from app.models import OrderStatus, AuthzStatus
from app.storage import get_storage

import logging
logger = logging.getLogger("acme.order")

router = APIRouter()


@router.post("/acme/new-order")
async def new_order(request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    kid = protected.get("kid")
    if not kid:
        raise MalformedError("kid required for new-order")

    storage = get_storage()
    account = storage.get_account_by_url(kid)
    if not account:
        raise AccountDoesNotExistError()
    logging.info(f"order account: {account}")
    identifiers = payload.get("identifiers")
    if not identifiers or not isinstance(identifiers, list):
        raise MalformedError("identifiers required")

    for ident in identifiers:
        if ident.get("type") not in ("dns", "ip", "remote-attestation"):
            raise MalformedError(f"Unsupported identifier type: {ident.get('type')}")

    not_before = payload.get("notBefore")
    not_after = payload.get("notAfter")
    logger.info(f"order identifiers:{identifiers} received")

    order = storage.create_order(
        account_id=account.id,
        identifiers=identifiers,
        not_before=not_before,
        not_after=not_after,
    )
    logger.info(f"order order:{order} received")
    resp = order.to_response()
    return JSONResponse(
        status_code=201,
        content=resp,
        headers={"Location": order.url},
    )


@router.post("/acme/order/{order_id}")
async def get_order(order_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()
    _verify_order_access(protected, storage, order_id)

    order = storage.get_order(order_id)
    if not order:
        raise MalformedError("Order not found")

    status = storage.check_order_authorizations(order_id)
    if status != order.status:
        storage.update_order(order_id, status=status)
        order.status = status

    return JSONResponse(content=order.to_response(), headers={"Location": order.url})


@router.post("/acme/order/{order_id}/finalize")
async def finalize_order(order_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()
    _verify_order_access(protected, storage, order_id)

    order = storage.get_order(order_id)
    if not order:
        raise MalformedError("Order not found")

    status = storage.check_order_authorizations(order_id)
    if order.status == OrderStatus.VALID:
        return JSONResponse(content=order.to_response(), headers={"Location": order.url})

    if status == OrderStatus.INVALID:
        storage.update_order(order_id, status=OrderStatus.INVALID)
        raise OrderNotReadyError()

    if status != OrderStatus.READY:
        raise OrderNotReadyError()

    csr_b64 = payload.get("csr")
    if not csr_b64:
        raise BadCsrError("Missing csr")

    try:
        csr_der = b64url_decode(csr_b64)
    except Exception:
        raise BadCsrError("Invalid base64url encoding of CSR")

    try:
        validate_csr_identifiers(csr_der, [i.model_dump() for i in order.identifiers])
    except BadCsrError:
        raise
    except Exception as e:
        raise BadCsrError(str(e))

    storage.update_order(order_id, status=OrderStatus.PROCESSING, csr=csr_b64)

    try:
        ca_key, ca_cert = ensure_ca()
        cert_pem = sign_csr(csr_der, ca_key, ca_cert)
        chain_pem = cert_pem + ca_cert.public_bytes(
            __import__("cryptography").hazmat.primitives.serialization.Encoding.PEM
        ).decode("ascii")

        cert = storage.create_certificate(order_id, order.account_id, cert_pem, chain_pem)
        cert_url = f"{settings.base_url}/acme/cert/{cert.id}"

        storage.update_order(order_id, status=OrderStatus.VALID, certificate=cert_url)
        order = storage.get_order(order_id)
    except Exception as e:
        storage.update_order(order_id, status=OrderStatus.INVALID, error={
            "type": "urn:ietf:params:acme:error:serverInternal",
            "detail": str(e),
        })
        raise

    return JSONResponse(content=order.to_response(), headers={"Location": order.url})


def _verify_order_access(protected: dict, storage, order_id: str):
    kid = protected.get("kid")
    if not kid:
        raise UnauthorizedError()
    account = storage.get_account_by_url(kid)
    if not account:
        raise AccountDoesNotExistError()
    order = storage.get_order(order_id)
    if not order or order.account_id != account.id:
        raise UnauthorizedError()
