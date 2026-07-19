from fastapi import APIRouter, Request, Response

from app.storage import get_storage

router = APIRouter()


@router.head("/acme/new-nonce")
async def new_nonce_head(request: Request):
    nonce = get_storage().create_nonce()
    return Response(
        status_code=200,
        headers={"Replay-Nonce": nonce, "Cache-Control": "no-store"},
    )


@router.get("/acme/new-nonce")
async def new_nonce_get(request: Request):
    nonce = get_storage().create_nonce()
    return Response(
        status_code=204,
        headers={"Replay-Nonce": nonce, "Cache-Control": "no-store"},
    )
