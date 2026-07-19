from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


def _fmt_ts(dt: datetime) -> str:
    """Format datetime as RFC 3339 with fractional seconds, e.g. 2015-03-01T14:09:07.99Z"""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    s = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
    # Trim trailing zeros but keep at least 2 fractional digits, then append Z
    frac = s.split(".")[1].rstrip("0")
    frac = frac[:6]  # microseconds max 6 digits
    if len(frac) < 2:
        frac = frac.ljust(2, "0")
    return s.split(".")[0] + "." + frac + "Z"


class IdentifierType(str, Enum):
    DNS = "dns"
    IP = "ip"
    REMOTE = "remote-attestation"


class Identifier(BaseModel):
    type: IdentifierType
    value: str


class ChallengeType(str, Enum):
    HTTP_01 = "http-01"
    DNS_01 = "dns-01"
    REMOTE_01 = "remote-attestation"


class AccountStatus(str, Enum):
    VALID = "valid"
    DEACTIVATED = "deactivated"
    REVOKED = "revoked"


class OrderStatus(str, Enum):
    PENDING = "pending"
    READY = "ready"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


class AuthzStatus(str, Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    DEACTIVATED = "deactivated"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ChallengeStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    VALID = "valid"
    INVALID = "invalid"


# --- Storage models ---

class Account(BaseModel):
    id: str
    jwk_thumbprint: str
    jwk: dict
    status: AccountStatus = AccountStatus.VALID
    contact: list[str] = Field(default_factory=list)
    terms_of_service_agreed: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def url(self) -> str:
        from app.config import settings
        return f"{settings.base_url}/acme/acct/{self.id}"


class Order(BaseModel):
    id: str
    account_id: str
    status: OrderStatus = OrderStatus.PENDING
    expires: datetime
    identifiers: list[Identifier] = Field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    authorizations: list[str] = Field(default_factory=list)
    certificate: Optional[str] = None
    csr: Optional[str] = None
    error: Optional[dict] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def url(self) -> str:
        from app.config import settings
        return f"{settings.base_url}/acme/order/{self.id}"

    @property
    def finalize_url(self) -> str:
        from app.config import settings
        return f"{settings.base_url}/acme/order/{self.id}/finalize"

    def to_response(self) -> dict:
        result = {
            "status": self.status.value,
            "expires": _fmt_ts(self.expires),
            "identifiers": [i.model_dump() for i in self.identifiers],
            "authorizations": self.authorizations,
            "finalize": self.finalize_url,
        }
        if self.not_before:
            result["notBefore"] = _fmt_ts(self.not_before)
        if self.not_after:
            result["notAfter"] = _fmt_ts(self.not_after)
        if self.certificate:
            result["certificate"] = self.certificate
        if self.error:
            result["error"] = self.error
        return result


class Authorization(BaseModel):
    id: str
    order_id: str
    identifier: Identifier
    status: AuthzStatus = AuthzStatus.PENDING
    expires: datetime
    challenges: list[str] = Field(default_factory=list)
    wildcard: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def url(self) -> str:
        from app.config import settings
        return f"{settings.base_url}/acme/authz/{self.id}"

    def to_response(self) -> dict:
        from app.storage import get_storage
        storage = get_storage()
        challenge_objects = []
        for chall_url in self.challenges:
            chall_id = chall_url.rstrip("/").split("/")[-1]
            chall = storage.get_challenge(chall_id)
            if chall:
                challenge_objects.append(chall.to_response())
        result = {
            "identifier": self.identifier.model_dump(),
            "status": self.status.value,
            "expires": _fmt_ts(self.expires),
            "challenges": challenge_objects,
        }
        if self.wildcard:
            result["wildcard"] = True
        return result


class Challenge(BaseModel):
    id: str
    authorization_id: str
    type: ChallengeType
    status: ChallengeStatus = ChallengeStatus.PENDING
    token: str
    validated: Optional[datetime] = None
    error: Optional[dict] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    freshness_nonce: Optional[str] = None
    attest_claims_hint: Optional[list[str]] = None
    verify_token: Optional[str] = None
    verifier_encryption_credential: Optional[str] = None

    @property
    def url(self) -> str:
        from app.config import settings
        return f"{settings.base_url}/acme/chall/{self.id}"

    def to_response(self) -> dict:
        result = {
            "type": self.type.value,
            "status": self.status.value,
            "url": self.url,
            "token": self.token,
        }
        if self.validated:
            result["validated"] = _fmt_ts(self.validated)
        if self.error:
            result["error"] = self.error
        if self.freshness_nonce:
            result["freshness_nonce"] = self.freshness_nonce
        if self.attest_claims_hint:
            result["attest_claims_hint"] = self.attest_claims_hint
        if self.verifier_encryption_credential:
            from app.config import settings
            result["verifier_encryption_credential"] = f"{settings.base_url}{self.verifier_encryption_credential}"
        return result


class Certificate(BaseModel):
    id: str
    order_id: str
    account_id: str
    cert_pem: str
    chain_pem: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    revoked: bool = False
