from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.acme_errors import (
    AccountDoesNotExistError,
    MalformedError,
    OrderNotReadyError,
    UnauthorizedError,
)
from app.crypto import verify_jws
from app.models import AuthzStatus, ChallengeStatus
from app.storage import get_storage

router = APIRouter()


def _verify_authz_access(protected: dict, storage, authz_id: str):
    kid = protected.get("kid")
    if not kid:
        raise UnauthorizedError()
    account = storage.get_account_by_url(kid)
    if not account:
        raise AccountDoesNotExistError()
    authz = storage.get_authorization(authz_id)
    if not authz:
        raise MalformedError("Authorization not found")
    order = storage.get_order(authz.order_id)
    if not order or order.account_id != account.id:
        raise UnauthorizedError()
    return authz, account


@router.post("/acme/authz/{authz_id}")
async def get_authorization(authz_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()
    authz, _ = _verify_authz_access(protected, storage, authz_id)

    _refresh_authz_status(storage, authz_id)

    authz = storage.get_authorization(authz_id)
    return JSONResponse(content=authz.to_response())


@router.post("/acme/authz/{authz_id}/finalize")
async def finalize_authorization(authz_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)

    storage = get_storage()
    authz, _ = _verify_authz_access(protected, storage, authz_id)

    _refresh_authz_status(storage, authz_id)

    authz = storage.get_authorization(authz_id)
    if authz.status != AuthzStatus.VALID:
        raise OrderNotReadyError()

    return JSONResponse(
        content=authz.to_response(),
        headers={"Location": authz.url},
    )


def _refresh_authz_status(storage, authz_id: str):
    """Check all challenges and update authorization status accordingly."""
    authz = storage.get_authorization(authz_id)
    if not authz or authz.status not in (AuthzStatus.PENDING,):
        return

    challenges = storage.get_challenges_by_authz(authz_id)
    if not challenges:
        return

    any_valid = any(c.status == ChallengeStatus.VALID for c in challenges)
    all_invalid = all(c.status == ChallengeStatus.INVALID for c in challenges)

    if any_valid:
        storage.update_authorization(authz_id, status=AuthzStatus.VALID)
    elif all_invalid:
        storage.update_authorization(authz_id, status=AuthzStatus.INVALID)


@router.post("/acme/authz/{authz_id}/deactivate")
async def deactivate_authorization(authz_id: str, request: Request):
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

    authz = storage.get_authorization(authz_id)
    if not authz:
        raise MalformedError("Authorization not found")

    from app.models import AuthzStatus
    authz = storage.update_authorization(authz_id, status=AuthzStatus.DEACTIVATED)

    return JSONResponse(content=authz.to_response())
