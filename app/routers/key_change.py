from fastapi import APIRouter, Request, Response

from app.acme_errors import MalformedError

router = APIRouter()


@router.post("/acme/key-change")
async def key_change(request: Request):
    """Key rollover - placeholder for future implementation."""
    return Response(
        status_code=501,
        content='{"type": "urn:ietf:params:acme:error:malformed", "detail": "Key change not implemented"}',
        media_type="application/json",
    )
