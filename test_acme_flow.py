"""Test ACME protocol flow against the local ACME server."""
import base64
import hashlib
import json
import os
import sys

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


BASE_URL = "http://localhost:8000"
client = httpx.Client(timeout=10.0)


def generate_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def jwk_from_key(key):
    pub = key.public_key()
    nums = pub.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(nums.x.to_bytes(32, "big")),
        "y": b64url_encode(nums.y.to_bytes(32, "big")),
    }


def jwk_thumbprint(jwk):
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        sort_keys=True, separators=(",", ":"),
    )
    return b64url_encode(hashlib.sha256(canonical.encode()).digest())


def sign_jws(protected: dict, payload: dict, key, use_jwk: bool = True):
    protected_b64 = b64url_encode(json.dumps(protected, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode()) if payload else b64url_encode(b"")
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der_sig)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    signature_b64 = b64url_encode(signature)

    body = {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }
    if use_jwk:
        body["protected"] = protected_b64  # jwk is already in protected

    return body


def get_nonce():
    resp = client.head(f"{BASE_URL}/acme/new-nonce")
    return resp.headers["replay-nonce"]


def test_acme_flow():
    print("=" * 60)
    print("Testing ACME Protocol Flow")
    print("=" * 60)

    # 1. Get directory
    print("\n1. GET /directory")
    resp = client.get(f"{BASE_URL}/directory")
    directory = resp.json()
    print(f"   Status: {resp.status_code}")
    print(f"   newNonce: {directory['newNonce']}")
    print(f"   newAccount: {directory['newAccount']}")
    print(f"   newOrder: {directory['newOrder']}")
    assert resp.status_code == 200

    # 2. Get nonce
    print("\n2. HEAD /acme/new-nonce")
    nonce = get_nonce()
    print(f"   Nonce: {nonce[:20]}...")

    # 3. Generate key and create account
    print("\n3. POST /acme/new-account")
    key = generate_ec_key()
    jwk = jwk_from_key(key)

    protected = {
        "alg": "ES256",
        "nonce": nonce,
        "url": f"{BASE_URL}/acme/new-account",
        "jwk": jwk,
    }
    payload = {
        "termsOfServiceAgreed": True,
        "contact": ["mailto:test@example.com"],
    }

    body = sign_jws(protected, payload, key, use_jwk=True)
    resp = client.post(f"{BASE_URL}/acme/new-account", json=body)
    account_resp = resp.json()
    account_url = resp.headers.get("location", "")
    print(f"   Status: {resp.status_code}")
    print(f"   Account URL: {account_url}")
    print(f"   Account Status: {account_resp.get('status')}")
    assert resp.status_code == 201
    assert account_resp["status"] == "valid"

    kid = account_url
    nonce = resp.headers["replay-nonce"]

    # 4. Create order
    print("\n4. POST /acme/new-order")
    protected = {
        "alg": "ES256",
        "nonce": nonce,
        "url": f"{BASE_URL}/acme/new-order",
        "kid": kid,
    }
    payload = {
        "identifiers": [{"type": "dns", "value": "test.example.com"}],
    }

    body = sign_jws(protected, payload, key, use_jwk=False)
    resp = client.post(f"{BASE_URL}/acme/new-order", json=body)
    order_resp = resp.json()
    order_url = resp.headers.get("location", "")
    print(f"   Status: {resp.status_code}")
    print(f"   Order URL: {order_url}")
    print(f"   Order Status: {order_resp.get('status')}")
    print(f"   Authorizations: {len(order_resp.get('authorizations', []))}")
    assert resp.status_code == 201
    assert order_resp["status"] == "pending"
    nonce = resp.headers["replay-nonce"]

    # 5. Get authorization
    authz_urls = order_resp.get("authorizations", [])
    if authz_urls:
        print("\n5. POST /acme/authz/{id}")
        authz_url = authz_urls[0]
        protected = {
            "alg": "ES256",
            "nonce": nonce,
            "url": authz_url,
            "kid": kid,
        }
        body = sign_jws(protected, {}, key, use_jwk=False)
        resp = client.post(authz_url, json=body)
        authz_resp = resp.json()
        print(f"   Status: {resp.status_code}")
        print(f"   Authz Status: {authz_resp.get('status')}")
        print(f"   Identifier: {authz_resp.get('identifier')}")
        print(f"   Challenges: {len(authz_resp.get('challenges', []))}")
        assert resp.status_code == 200
        nonce = resp.headers["replay-nonce"]

        # 6. Get challenge details
        challenge_urls = authz_resp.get("challenges", [])
        for chall_url in challenge_urls:
            chall_id = chall_url.rstrip("/").split("/")[-1]
            print(f"\n6. Challenge details from authz response")

        # Display challenge info
        if challenge_urls:
            print(f"   HTTP-01 Challenge URL: {[u for u in challenge_urls if 'chall' in u]}")

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)

    # Print summary for client testing
    print(f"\nACME Directory URL: {BASE_URL}/directory")
    print(f"CA Certificate: ca/ca_cert.pem")
    print(f"\nTo test with certbot:")
    print(f"  certbot certonly --standalone --server {BASE_URL}/directory")
    print(f"\nTo test with acme.sh:")
    print(f"  acme.sh --issue -d test.example.com --server {BASE_URL}/directory")


if __name__ == "__main__":
    try:
        test_acme_flow()
    except Exception as e:
        print(f"\nTest failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
