from __future__ import annotations
import hashlib
import os
import time
import threading
from typing import Optional

from jose import jwe
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


from app.crypto import generate_token
from app.models import (
    Account, AccountStatus,
    Authorization, AuthzStatus,
    Certificate,
    Challenge, ChallengeStatus, ChallengeType,
    Identifier, IdentifierType,
    Order, OrderStatus,
)

import logging
logger = logging.getLogger("acme.storage")

class Storage:
    def __init__(self):
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}
        self._accounts: dict[str, Account] = {}
        self._account_by_thumbprint: dict[str, str] = {}
        self._orders: dict[str, Order] = {}
        self._authorizations: dict[str, Authorization] = {}
        self._challenges: dict[str, Challenge] = {}
        self._certificates: dict[str, Certificate] = {}
        self._verifies: dict[str, rsa.RSAPrivateKey] = {}
        self._nonce_ttl = 3600  # 1 hour

    # --- Nonce management ---

    def create_nonce(self) -> str:
        nonce = generate_token()
        with self._lock:
            self._nonces[nonce] = time.time()
        return nonce

    def consume_nonce(self, nonce: str) -> bool:
        with self._lock:
            created = self._nonces.pop(nonce, None)
            if created is None:
                return False
            if time.time() - created > self._nonce_ttl:
                return False
            return True

    def cleanup_nonces(self):
        cutoff = time.time() - self._nonce_ttl
        with self._lock:
            expired = [n for n, t in self._nonces.items() if t < cutoff]
            for n in expired:
                del self._nonces[n]

    # --- Account management ---

    def create_account(self, jwk: dict, contact: list[str], terms_agreed: bool) -> Account:
        from app.crypto import jwk_thumbprint
        thumbprint = jwk_thumbprint(jwk)

        with self._lock:
            existing_id = self._account_by_thumbprint.get(thumbprint)
            if existing_id:
                return self._accounts[existing_id]

            account_id = generate_token()
            account = Account(
                id=account_id,
                jwk_thumbprint=thumbprint,
                jwk=jwk,
                contact=contact,
                terms_of_service_agreed=terms_agreed,
            )
            self._accounts[account_id] = account
            self._account_by_thumbprint[thumbprint] = account_id
            return account

    def get_account(self, account_id: str) -> Optional[Account]:
        return self._accounts.get(account_id)

    def get_account_by_thumbprint(self, thumbprint: str) -> Optional[Account]:
        with self._lock:
            account_id = self._account_by_thumbprint.get(thumbprint)
            if account_id:
                return self._accounts.get(account_id)
            return None

    def get_account_by_url(self, url: str) -> Optional[Account]:
        account_id = url.rstrip("/").split("/")[-1]
        return self.get_account(account_id)

    def update_account(self, account_id: str, **kwargs) -> Optional[Account]:
        with self._lock:
            account = self._accounts.get(account_id)
            if not account:
                return None
            for k, v in kwargs.items():
                if hasattr(account, k):
                    setattr(account, k, v)
            return account

    # --- Order management ---

    def create_order(self, account_id: str, identifiers: list[dict],
                     not_before: Optional[str] = None,
                     not_after: Optional[str] = None) -> Order:
        from datetime import datetime, timedelta, timezone
        logger.info("storage create order in")
        with self._lock:
            order_id = generate_token()
            expires = datetime.now(timezone.utc) + timedelta(hours=settings_order_validity_hours())

            idents = [Identifier(type=IdentifierType(i["type"]), value=i["value"]) for i in identifiers]
            logger.info(f"storage create order idents: {idents}")
            order = Order(
                id=order_id,
                account_id=account_id,
                expires=expires,
                identifiers=idents,
            )
            logging.info(f"storage create order order id: {order_id}")
            for ident in idents:
                authz = self._create_authorization(order_id, ident, expires)
                order.authorizations.append(authz.url)

            self._orders[order_id] = order
            return order

    def _create_authorization(self, order_id: str, identifier: Identifier,
                              expires) -> Authorization:
        from datetime import datetime, timezone

        authz_id = generate_token()
        wildcard = identifier.value.startswith("*.")
        authz = Authorization(
            id=authz_id,
            order_id=order_id,
            identifier=identifier,
            expires=expires,
            wildcard=wildcard,
        )

        challenge_types = [ChallengeType.DNS_01] if wildcard else [ChallengeType.HTTP_01, ChallengeType.DNS_01, ChallengeType.REMOTE_01]
        for ctype in challenge_types:
            logger.info(f"storage _create_authorization idents: {ctype}")
            chall = self._create_challenge(authz_id, ctype, identifier)
            authz.challenges.append(chall.url)

        self._authorizations[authz_id] = authz
        return authz

    def _create_challenge(self, authz_id: str, ctype: ChallengeType, identifier: Identifier) -> Challenge:
        logger.info("into _create_challenge now")
        chall_id = generate_token()
        chall = Challenge(
            id=chall_id,
            authorization_id=authz_id,
            type=ctype,
            token=generate_token(),
        )
        logger.info(f"into _create_challenge: chall id: {chall_id}")
        if ctype.value == "remote-attestation":
            from app.config import settings
            chall.attest_claims_hint = settings.hint_config.get(identifier.value, [])
            chall.freshness_nonce = generate_token()
            verify_token =  generate_token()
            chall.verify_token = verify_token
            self._verifies[verify_token] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            chall.verifier_encryption_credential = "/acme/verify/" + verify_token
        self._challenges[chall_id] = chall
        return chall

    def get_order(self, order_id: str) -> Optional[Order]:
        return self._orders.get(order_id)

    def get_orders_by_account(self, account_id: str) -> list[Order]:
        return [o for o in self._orders.values() if o.account_id == account_id]

    def update_order(self, order_id: str, **kwargs) -> Optional[Order]:
        with self._lock:
            order = self._orders.get(order_id)
            if not order:
                return None
            for k, v in kwargs.items():
                if hasattr(order, k):
                    setattr(order, k, v)
            return order

    def check_order_authorizations(self, order_id: str) -> OrderStatus:
        order = self._orders.get(order_id)
        if not order:
            return OrderStatus.INVALID

        all_valid = True
        any_invalid = False

        for authz_url in order.authorizations:
            authz_id = authz_url.rstrip("/").split("/")[-1]
            authz = self._authorizations.get(authz_id)
            if not authz:
                all_valid = False
                continue
            if authz.status == AuthzStatus.INVALID:
                any_invalid = True
            elif authz.status != AuthzStatus.VALID:
                all_valid = False

        if any_invalid:
            return OrderStatus.INVALID
        if all_valid:
            return OrderStatus.READY
        return OrderStatus.PENDING

    # --- Authorization management ---

    def get_authorization(self, authz_id: str) -> Optional[Authorization]:
        return self._authorizations.get(authz_id)

    def update_authorization(self, authz_id: str, **kwargs) -> Optional[Authorization]:
        with self._lock:
            authz = self._authorizations.get(authz_id)
            if not authz:
                return None
            for k, v in kwargs.items():
                if hasattr(authz, k):
                    setattr(authz, k, v)
            return authz

    # --- Challenge management ---

    def get_challenge(self, chall_id: str) -> Optional[Challenge]:
        return self._challenges.get(chall_id)

    def get_challenges_by_authz(self, authz_id: str) -> list[Challenge]:
        return [c for c in self._challenges.values() if c.authorization_id == authz_id]

    def update_challenge(self, chall_id: str, **kwargs) -> Optional[Challenge]:
        with self._lock:
            chall = self._challenges.get(chall_id)
            if not chall:
                return None
            for k, v in kwargs.items():
                if hasattr(chall, k):
                    setattr(chall, k, v)
            return chall

    # --- Certificate management ---

    def create_certificate(self, order_id: str, account_id: str,
                           cert_pem: str, chain_pem: str) -> Certificate:
        cert_id = generate_token()
        cert = Certificate(
            id=cert_id,
            order_id=order_id,
            account_id=account_id,
            cert_pem=cert_pem,
            chain_pem=chain_pem,
        )
        self._certificates[cert_id] = cert
        return cert

    def get_certificate(self, cert_id: str) -> Optional[Certificate]:
        return self._certificates.get(cert_id)

    def get_rsa_private(self, verify_id: str) -> Optional[rsa.RSAPrivateKey]:
        return self._verifies.get(verify_id)
    
    def get_certificate_by_order(self, order_id: str) -> Optional[Certificate]:
        for cert in self._certificates.values():
            if cert.order_id == order_id:
                return cert
        return None


_storage: Optional[Storage] = None


def settings_order_validity_hours():
    from app.config import settings
    return settings.order_validity_hours


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage
