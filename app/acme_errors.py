from fastapi import HTTPException
from fastapi.responses import JSONResponse


class AcmeError(HTTPException):
    def __init__(self, typ: str, detail: str, status_code: int = 400):
        self.typ = typ
        self.detail = detail
        self.status_code = status_code

    def to_response(self) -> JSONResponse:
        return JSONResponse(
            status_code=self.status_code,
            content={"type": self.typ, "detail": self.detail},
        )


class BadNonceError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:badNonce", "Invalid or expired nonce", 400)



class BadVerifyError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:bad:verify", "Invalid verify", 400)


class BadSignatureAlgorithmError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:badSignatureAlgorithm", "Unsupported signature algorithm", 400)


class InvalidContactError(AcmeError):
    def __init__(self, contact: str):
        super().__init__("urn:ietf:params:acme:error:invalidContact", f"Invalid contact: {contact}", 400)


class UnsupportedContactError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:unsupportedContact", "Unsupported contact type", 400)


class AccountDoesNotExistError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:accountDoesNotExist", "Account does not exist", 400)


class MalformedError(AcmeError):
    def __init__(self, detail: str = "Malformed request"):
        super().__init__("urn:ietf:params:acme:error:malformed", detail, 400)


class UnauthorizedError(AcmeError):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__("urn:ietf:params:acme:error:unauthorized", detail, 403)


class OrderNotReadyError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:orderNotReady", "Order is not ready for finalization", 403)


class RejectedIdentifierError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:rejectedIdentifier", "Rejected identifier", 400)


class RateLimitedError(AcmeError):
    def __init__(self, detail: str = "Rate limited"):
        super().__init__("urn:ietf:params:acme:error:rateLimited", detail, 429)


class BadCsrError(AcmeError):
    def __init__(self, detail: str = "Bad CSR"):
        super().__init__("urn:ietf:params:acme:error:badCSR", detail, 400)


class ConflictError(AcmeError):
    def __init__(self, detail: str = "Conflict"):
        super().__init__("urn:ietf:params:acme:error:malformed", detail, 409)


class ServerInternalError(AcmeError):
    def __init__(self, detail: str = "Internal server error"):
        super().__init__("urn:ietf:params:acme:error:serverInternal", detail, 500)


class AlreadyRevokedError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:alreadyRevoked", "Certificate already revoked", 400)


class BadRevocationReasonError(AcmeError):
    def __init__(self):
        super().__init__("urn:ietf:params:acme:error:badRevocationReason", "Bad revocation reason", 400)
