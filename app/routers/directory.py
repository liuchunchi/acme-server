from fastapi import APIRouter, Request

from app.config import settings

router = APIRouter()


@router.get("/directory")
async def get_directory(request: Request):
    base = settings.base_url
    return {
        "newNonce": f"{base}/acme/new-nonce",
        "newAccount": f"{base}/acme/new-account",
        "newOrder": f"{base}/acme/new-order",
        "revokeCert": f"{base}/acme/revoke-cert",
        "keyChange": f"{base}/acme/key-change",
        "meta": {
            "termsOfService": f"{base}/terms",
            "website": base,
            "caaIdentities": [settings.base_url.split("//")[1].split("/")[0].split(":")[0]],
            "externalAccountRequired": False,
        },
    }
