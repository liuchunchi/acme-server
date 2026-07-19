import asyncio
import hashlib
import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.acme_errors import (
    AccountDoesNotExistError,
    MalformedError,
    UnauthorizedError,
)
from app.config import settings
from app.crypto import verify_jws, b64url_encode, jwk_thumbprint, b64url_decode, jwe_payload_to_compact
from app.models import AuthzStatus, ChallengeStatus
from app.storage import get_storage
from jose import jwe
logger = logging.getLogger("acme.challenge")

router = APIRouter()


@router.post("/acme/chall/{chall_id}")
async def handle_challenge(chall_id: str, request: Request):
    body = await request.json()
    url = str(request.url)
    protected, payload, thumbprint = verify_jws(body, url)
    payload_b64 = body.get("payload")
    payload_raw = b64url_decode(payload_b64)
    logger.info(f"challenge payload: {payload_b64}, {payload_raw}")
    
    storage = get_storage()

    kid = protected.get("kid")
    if not kid:
        raise UnauthorizedError()
    account = storage.get_account_by_url(kid)
    if not account:
        raise AccountDoesNotExistError()

    chall = storage.get_challenge(chall_id)
    if not chall:
        raise MalformedError("Challenge not found")

    authz = storage.get_authorization(chall.authorization_id)
    if not authz:
        raise MalformedError("Authorization not found")

    verify_token = chall.verify_token
    if verify_token is not None:
        private_key = storage.get_rsa_private(verify_token)
        if private_key is None:
            logger.warning(f"verify token {verify_token} has no matching private key")
        else:
            # The attestation payload is a JWE in flattened JSON serialization
            # (optionally wrapped as a JSON string). python-jose only decrypts
            # the compact form, so unwrap/rebuild it first.
            compact = jwe_payload_to_compact(payload_raw)
            if compact is not None:
                try:
                    decrypted_payload = jwe.decrypt(compact, private_key)
                    logger.info(f"decrypted attestation: {decrypted_payload!r}")
                    # TODO: feed decrypted_payload into attestation validation
                except Exception as e:
                    logger.warning(f"JWE decrypt failed for challenge {chall_id}: {e}")
                
    order = storage.get_order(authz.order_id)
    if not order or order.account_id != account.id:
        raise UnauthorizedError()

    # Mark as processing
    storage.update_challenge(chall_id, status=ChallengeStatus.PROCESSING)

    # Trigger async validation
    asyncio.create_task(
        _validate_challenge(chall_id, account.jwk)
    )

    chall = storage.get_challenge(chall_id)
    return JSONResponse(
        content=chall.to_response(),
        headers={"Link": f'<{authz.url}>;rel="up"'},
    )


async def _validate_challenge(chall_id: str, account_jwk: dict):
    """Validate the challenge in background."""
    storage = get_storage()
    chall = storage.get_challenge(chall_id)
    if not chall:
        return

    authz = storage.get_authorization(chall.authorization_id)
    if not authz:
        return

    thumbprint = jwk_thumbprint(account_jwk)
    key_authorization = f"{chall.token}.{thumbprint}"

    success = False

    if settings.auto_accept_challenges:
        success = True
    elif chall.type.value == "http-01":
        success = await _validate_http01(authz.identifier.value, chall.token, key_authorization)
    elif chall.type.value == "dns-01":
        expected = b64url_encode(hashlib.sha256(key_authorization.encode("ascii")).digest())
        success = await _validate_dns01(authz.identifier.value, expected)

    now = datetime.now(timezone.utc)
    if success:
        storage.update_challenge(chall_id, status=ChallengeStatus.VALID, validated=now)
        storage.update_authorization(authz.id, status=AuthzStatus.VALID)
        logger.info(f"Challenge {chall_id} validated successfully")
    else:
        storage.update_challenge(
            chall_id,
            status=ChallengeStatus.INVALID,
            error={
                "type": "urn:ietf:params:acme:error:incorrectResponse",
                "detail": "Challenge validation failed",
            },
        )
        # Check if all challenges are invalid
        all_challenges = storage.get_challenges_by_authz(authz.id)
        all_invalid = all(c.status == ChallengeStatus.INVALID for c in all_challenges)
        if all_invalid:
            storage.update_authorization(authz.id, status=AuthzStatus.INVALID)
        logger.warning(f"Challenge {chall_id} validation failed")


async def _validate_http01(domain: str, token: str, key_authz: str) -> bool:
    """Validate HTTP-01 challenge by fetching the token URL."""
    url = f"http://{domain}/.well-known/acme-challenge/{token}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                body = resp.text.strip()
                return body == key_authz
            return False
    except Exception as e:
        logger.warning(f"HTTP-01 validation failed for {domain}: {e}")
        return False


async def _validate_dns01(domain: str, expected_value: str) -> bool:
    """Validate DNS-01 challenge using DNS TXT lookup."""
    import random

    lookup_domain = f"_acme-challenge.{domain}"
    resolvers = settings.dns_resolvers

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = resolvers
        answers = resolver.resolve(lookup_domain, "TXT")
        for rdata in answers:
            for txt in rdata.strings:
                if txt.decode("utf-8") == expected_value:
                    return True
        return False
    except ImportError:
        # Fallback: use nslookup
        resolver = random.choice(resolvers)
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=TXT", lookup_domain, resolver,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode("utf-8", errors="replace")
            return expected_value in output
        except Exception as e:
            logger.warning(f"DNS-01 validation failed for {domain}: {e}")
            return False
    except Exception as e:
        logger.warning(f"DNS-01 validation failed for {domain}: {e}")
        return False
