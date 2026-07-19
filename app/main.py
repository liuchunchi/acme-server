import json
import logging
import argparse
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from app.acme_errors import AcmeError
from app.config import settings
from app.routers import (
    directory,
    nonce,
    account,
    order,
    authz,
    challenge,
    certificate,
    key_change,
    verify,
)
from app.storage import get_storage

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

_logger = logging.getLogger("acme")
_logger.setLevel(logging.INFO)
_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

# Console handler
_console = logging.StreamHandler()
_console.setFormatter(_formatter)
_logger.addHandler(_console)

# File handler with rotation (10MB per file, keep 5 backups)
_file = RotatingFileHandler(
    LOG_DIR / "acme.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8",
)
_file.setFormatter(_formatter)
_logger.addHandler(_file)

logger = _logger.getChild("api")


def create_app() -> FastAPI:
    app = FastAPI(title="ACME Server", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "HEAD", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def request_logging(request: Request, call_next):
        path = request.url.path
        method = request.method

        # Log request
        log_input = ""
        if method in ("POST", "PUT", "PATCH"):
            body_bytes = await request.body()
            try:
                body_json = json.loads(body_bytes)
                log_input = json.dumps(body_json, ensure_ascii=False)
            except Exception:
                log_input = body_bytes.decode("utf-8", errors="replace")
        logger.info(f">>> {method} {path} | input: {log_input}")

        response = await call_next(request)

        # Add nonce header
        if path.startswith("/acme/") or path == "/directory":
            nonce = get_storage().create_nonce()
            response.headers["Replay-Nonce"] = nonce
            response.headers["Cache-Control"] = "no-store"

        # Log response
        status = response.status_code
        log_output = ""
        # Read response body for logging
        if hasattr(response, "body_iterator"):
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk)
            body_bytes = b"".join(chunks)
            # Reconstruct response with captured body
            from starlette.responses import Response as StarletteResponse
            new_response = StarletteResponse(
                content=body_bytes,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.media_type,
            )
            response = new_response
            # Format body for logging
            try:
                body_json = json.loads(body_bytes)
                log_output = json.dumps(body_json, ensure_ascii=False)
            except Exception:
                text = body_bytes.decode("utf-8", errors="replace")
                log_output = text[:2000]
        logger.info(f"<<< {method} {path} | status: {status} | response: {log_output}")

        return response

    @app.exception_handler(AcmeError)
    async def acme_error_handler(request: Request, exc: AcmeError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"type": exc.typ, "detail": exc.detail},
        )

    app.include_router(directory.router)
    app.include_router(nonce.router)
    app.include_router(account.router)
    app.include_router(order.router)
    app.include_router(authz.router)
    app.include_router(challenge.router)
    app.include_router(certificate.router)
    app.include_router(key_change.router)
    app.include_router(verify.router)

    @app.on_event("startup")
    async def startup():
        from app.crypto import ensure_ca
        ensure_ca()
        logger.info(f"ACME Server starting at {settings.base_url}")
        logger.info(f"Directory: {settings.base_url}/directory")

    return app


app = create_app()


def main():
    parser = argparse.ArgumentParser(description="ACME Server")
    parser.add_argument("--host", default=settings.host, help="Bind host")
    parser.add_argument("--port", type=int, default=settings.port, help="Bind port")
    parser.add_argument("--base-url", default=None, help="External base URL")
    args = parser.parse_args()

    if args.base_url:
        settings.base_url = args.base_url

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
