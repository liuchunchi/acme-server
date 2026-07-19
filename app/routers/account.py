from fastapi import APIRouter, Request, Response

from app.acme_errors import (
    AcmeError,
    AccountDoesNotExistError,
    MalformedError,
    UnauthorizedError,
)
from app.crypto import verify_jws
from app.models import AccountStatus
from app.storage import get_storage

router = APIRouter()


@router.post("/acme/new-account")
async def new_account(request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()

    contact = payload.get("contact", [])
    terms_agreed = payload.get("termsOfServiceAgreed", False)
    only_existing = payload.get("onlyReturnExisting", False)

    jwk = protected.get("jwk")
    if not jwk:
        raise MalformedError("jwk required for new-account")

    existing = storage.get_account_by_thumbprint(thumbprint)
    if existing:
        if only_existing:
            return Response(
                status_code=200,
                content=existing.model_dump_json(),
                media_type="application/json",
                headers={"Location": existing.url},
            )
        return _account_response(existing, status_code=200)

    if only_existing:
        raise AccountDoesNotExistError()

    account = storage.create_account(jwk, contact, terms_agreed)
    return _account_response(account, status_code=201)


@router.post("/acme/acct/{account_id}")
async def update_account(account_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()
    account = storage.get_account(account_id)
    if not account:
        raise AccountDoesNotExistError()

    kid = protected.get("kid", "")
    if not kid.endswith(f"/acme/acct/{account_id}"):
        raise UnauthorizedError()

    updates = {}
    if "contact" in payload:
        updates["contact"] = payload["contact"]
    if "status" in payload:
        if payload["status"] == "deactivated":
            updates["status"] = AccountStatus.DEACTIVATED
        else:
            raise MalformedError(f"Cannot set status to {payload['status']}")

    if updates:
        account = storage.update_account(account_id, **updates)
        if not account:
            raise AccountDoesNotExistError()

    return _account_response(account, status_code=200)


def _account_response(account, status_code: int = 200):
    from fastapi.responses import JSONResponse

    return JSONResponse(
        status_code=status_code,
        content={
            "status": account.status.value,
            "contact": account.contact,
            "termsOfServiceAgreed": account.terms_of_service_agreed,
            "orders": f"{account.url}/orders",
        },
        headers={"Location": account.url},
    )
