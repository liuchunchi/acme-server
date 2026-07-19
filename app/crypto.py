from __future__ import annotations
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePublicNumbers,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509.oid import NameOID, ExtensionOID

from app.acme_errors import (
    BadSignatureAlgorithmError,
    MalformedError,
)
from app.config import settings


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


SUPPORTED_ALGS = {"RS256", "ES256", "ES384", "ES512", "EdDSA"}


def _b64url_to_int(s: str) -> int:
    return int.from_bytes(b64url_decode(s), byteorder="big")


def _int_to_b64url(n: int, length: Optional[int] = None) -> str:
    data = n.to_bytes(length or (n.bit_length() + 7) // 8, byteorder="big")
    return b64url_encode(data)


def _jwk_to_public_key(jwk: dict) -> Any:
    kty = jwk.get("kty")
    if kty == "RSA":
        n = _b64url_to_int(jwk["n"])
        e = _b64url_to_int(jwk["e"])
        return RSAPublicNumbers(e, n).public_key()
    elif kty == "EC":
        crv = jwk["crv"]
        curve_map = {
            "P-256": SECP256R1(),
            "P-384": SECP384R1(),
            "P-521": SECP521R1(),
        }
        if crv not in curve_map:
            raise MalformedError(f"Unsupported curve: {crv}")
        x = _b64url_to_int(jwk["x"])
        y = _b64url_to_int(jwk["y"])
        numbers = EllipticCurvePublicNumbers(x, y, curve_map[crv])
        return numbers.public_key()
    elif kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise MalformedError(f"Unsupported OKP curve: {jwk.get('crv')}")
        x = b64url_decode(jwk["x"])
        return ed25519.Ed25519PublicKey.from_public_bytes(x)
    else:
        raise MalformedError(f"Unsupported key type: {kty}")


def jwk_thumbprint(jwk: dict) -> str:
    kty = jwk.get("kty")
    if kty == "RSA":
        canonical = json.dumps(
            {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]},
            sort_keys=True, separators=(",", ":"),
        )
    elif kty == "EC":
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]},
            sort_keys=True, separators=(",", ":"),
        )
    elif kty == "OKP":
        canonical = json.dumps(
            {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]},
            sort_keys=True, separators=(",", ":"),
        )
    else:
        raise MalformedError(f"Cannot compute thumbprint for kty={kty}")

    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return b64url_encode(digest)


def verify_jws(body: dict, expected_url: str) -> tuple[dict, dict | bytes, str]:
    """Verify a JWS message and return (protected_header, payload, jwk_thumbprint).

    payload is normally a parsed dict. For remote-attestation challenges the
    JWS payload carries an embedded JWE (not JSON); in that case payload is the
    raw decoded bytes and the caller is responsible for decrypting them.
    """
    protected_b64 = body.get("protected")
    payload_b64 = body.get("payload")
    signature_b64 = body.get("signature")

    if not all([protected_b64, payload_b64 is not None, signature_b64]):
        raise MalformedError("Invalid JWS format")

    protected_raw = b64url_decode(protected_b64)
    protected = json.loads(protected_raw)

    alg = protected.get("alg", "")
    if alg not in SUPPORTED_ALGS:
        raise BadSignatureAlgorithmError()

    nonce = protected.get("nonce")
    if not nonce:
        raise MalformedError("Missing nonce in protected header")

    url = protected.get("url")
    if url != expected_url:
        raise MalformedError(f"URL mismatch: expected {expected_url}, got {url}")

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = b64url_decode(signature_b64)

    jwk = protected.get("jwk")
    kid = protected.get("kid")

    if jwk:
        public_key = _jwk_to_public_key(jwk)
        thumbprint = jwk_thumbprint(jwk)
    elif kid:
        from app.storage import get_storage
        storage = get_storage()
        account = storage.get_account_by_url(kid)
        if not account:
            from app.acme_errors import AccountDoesNotExistError
            raise AccountDoesNotExistError()
        public_key = _jwk_to_public_key(account.jwk)
        thumbprint = account.jwk_thumbprint
    else:
        raise MalformedError("Missing jwk or kid in protected header")

    _verify_signature(public_key, alg, signing_input, signature)

    payload_raw = b64url_decode(payload_b64)
    if not payload_raw:
        payload: dict | bytes = {}
    else:
        try:
            payload = json.loads(payload_raw)
        except (json.JSONDecodeError, ValueError):
            # Non-JSON payload (e.g. an embedded JWE for remote-attestation
            # challenges). Pass the raw bytes through to the caller.
            payload = payload_raw

    return protected, payload, thumbprint


def jwe_payload_to_compact(payload_raw: bytes) -> Optional[str]:
    """Extract a JWE compact-serialization string from an attestation payload.

    The payload may be either a JWE in flattened JSON serialization, or that
    same JSON wrapped as a JSON string value (what the JWS ``payload`` field
    decodes to in the attestation flow). Returns the compact serialization
    ``protected.encrypted_key.iv.ciphertext.tag`` so it can be fed to
    ``jose.jwe.decrypt`` (which only handles the compact form), or None if
    payload_raw is not a JWE (e.g. a normal JSON object like ``{}``).
    """
    try:
        decoded = json.loads(payload_raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(decoded, str):
        # JSON-string-wrapped form: decode once more to get the JWE object.
        try:
            decoded = json.loads(decoded)
        except (json.JSONDecodeError, ValueError):
            return None
    if not isinstance(decoded, dict) or "ciphertext" not in decoded:
        return None
    return ".".join(
        decoded.get(k, "") for k in ("protected", "encrypted_key", "iv", "ciphertext", "tag")
    )


def _verify_signature(public_key: Any, alg: str, data: bytes, signature: bytes):
    if alg == "RS256":
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    elif alg in ("ES256", "ES384", "ES512"):
        hash_alg = {
            "ES256": hashes.SHA256(),
            "ES384": hashes.SHA384(),
            "ES512": hashes.SHA512(),
        }[alg]
        # DER-encoded signature
        try:
            public_key.verify(signature, data, ECDSA(hash_alg))
        except Exception:
            # Try converting from raw (r || s) format
            key_size_bytes = {
                "ES256": 32,
                "ES384": 48,
                "ES512": 66,
            }[alg]
            if len(signature) == key_size_bytes * 2:
                r = int.from_bytes(signature[:key_size_bytes], "big")
                s = int.from_bytes(signature[key_size_bytes:], "big")
                der_sig = utils.encode_dss_signature(r, s)
                public_key.verify(der_sig, data, ECDSA(hash_alg))
            else:
                raise
    elif alg == "EdDSA":
        public_key.verify(signature, data)
    else:
        raise BadSignatureAlgorithmError()


def generate_token() -> str:
    return b64url_encode(os.urandom(32))


# --- CA certificate management ---

def ensure_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Ensure CA key and cert exist, generating them if needed."""
    key_path = settings.ca_key_path
    cert_path = settings.ca_cert_path

    if key_path.exists() and cert_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return key, cert

    return _generate_ca()


def _generate_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=settings.ca_key_size)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, settings.ca_country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, settings.ca_organization),
        x509.NameAttribute(NameOID.COMMON_NAME, settings.ca_common_name),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    settings.ca_key_path.parent.mkdir(parents=True, exist_ok=True)
    settings.ca_key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    settings.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return key, cert


def sign_csr(csr_der: bytes, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate) -> str:
    """Sign a CSR and return the certificate PEM."""
    csr = x509.load_der_x509_csr(csr_der)

    # Validate CSR subject matches expected
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=settings.cert_validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    # Copy Subject Alternative Names from CSR
    try:
        san = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        builder = builder.add_extension(san.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def validate_csr_identifiers(csr_der: bytes, identifiers: list[dict]) -> None:
    """Validate that CSR contains matching identifiers."""
    csr = x509.load_der_x509_csr(csr_der)

    san_names = set()
    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value.get_values_for_type(x509.DNSName):
            san_names.add(name.lower())
    except x509.ExtensionNotFound:
        pass

    for ident in identifiers:
        if ident["type"] == "dns":
            value = ident["value"].lower()
            if value not in san_names and f"*.{value.lstrip('*.')}" not in san_names:
                from app.acme_errors import BadCsrError
                raise BadCsrError(f"CSR does not include identifier: {value}")
