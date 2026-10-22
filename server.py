# -*- coding: utf-8 -*-
"""
Meikova Auth Gateway & Universal SSO Service
Independent, Production-Ready Identity & Authentication Gateway for Render Cloud & Edge.
Connects to Turso Cloud SQLite (`meikova-auth`) and issues 30-day Ed25519 JWT tokens.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Optional

AUTH_DIR = Path(__file__).resolve().parent
if str(AUTH_DIR) not in sys.path:
    sys.path.insert(0, str(AUTH_DIR))

# Standard library .env loader
def _load_env():
    env_file = AUTH_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))

_load_env()

from fastapi import FastAPI, HTTPException, Request, Header, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.auth_gateway import AuthGateway, gateway_instance
from core.universal_sso import verify_universal_token, issue_universal_token

app = FastAPI(
    title="Meikova Auth Gateway & Universal SSO",
    description="Centralized Identity & Universal Ed25519 SSO Service for Meikova Ecosystem",
    version="1.0.0",
)

# CORS configuration
origins_env = os.environ.get("CORS_ORIGINS", "*").strip()
allow_origins = ["*"] if origins_env == "*" else [o.strip() for o in origins_env.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static assets (favicons, manifests)
static_dir = AUTH_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# Pydantic Request Models
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, description="Username (minimum 3 characters)")
    password: str = Field(..., min_length=6, description="Password (minimum 6 characters)")
    email: Optional[str] = Field(None, description="Optional email address")
    display_name: Optional[str] = Field(None, description="Optional public display name")


class LoginRequest(BaseModel):
    username: Optional[str] = Field(None, description="Username or email identifier")
    identifier: Optional[str] = Field(None, description="Alternative key for username/email")
    password: str = Field(..., description="Account password")


class GoogleAuthRequest(BaseModel):
    credential: str = Field(..., description="Google ID Token JWT")


class VerifyRequest(BaseModel):
    token: Optional[str] = Field(None, description="Ed25519 SSO Token")


# Routes
@app.get("/")
def root_info():
    return {
        "service": "meikova-auth-gateway",
        "name": "Meikova Auth Gateway & Universal SSO",
        "version": "1.0.0",
        "status": "online",
        "architecture": "turso-cloud-libsql-ed25519",
        "docs_url": "/docs",
        "endpoints": {
            "health": "/health",
            "register": "POST /api/auth/register",
            "login": "POST /api/auth/login",
            "google": "POST /api/auth/google",
            "me": "GET /api/auth/me",
            "verify": "GET|POST /api/auth/verify",
            "keys": "GET /api/auth/keys",
            "jwks": "GET /.well-known/jwks.json",
        }
    }


@app.get("/health")
def health_check():
    backend = "turso" if gateway_instance.is_turso else "sqlite_local"
    db_ok = False
    try:
        row = gateway_instance.fetchone("SELECT 1")
        db_ok = row is not None and (row[0] == 1 if hasattr(row, '__getitem__') else True)
    except Exception as e:
        db_ok = False

    from core.universal_sso import sso_instance
    has_priv = bool(sso_instance.private_key_pem)
    has_pub = bool(sso_instance.public_key_pem)

    return {
        "status": "healthy" if db_ok and has_pub else "degraded",
        "database": {
            "backend": backend,
            "connected": db_ok,
            "turso_configured": gateway_instance.is_turso,
        },
        "crypto": {
            "algorithm": "Ed25519",
            "private_key_loaded": has_priv,
            "public_key_loaded": has_pub,
        }
    }


@app.get("/login", response_class=FileResponse)
def get_login_page(client_id: Optional[str] = None, origin: Optional[str] = None, redirect_uri: Optional[str] = None):
    sso_page = static_dir / "sso.html"
    if sso_page.exists():
        return FileResponse(sso_page, media_type="text/html")
    raise HTTPException(status_code=404, detail="SSO Portal UI not found")


@app.get("/register", response_class=FileResponse)
def get_register_page(client_id: Optional[str] = None, origin: Optional[str] = None, redirect_uri: Optional[str] = None):
    sso_page = static_dir / "sso.html"
    if sso_page.exists():
        return FileResponse(sso_page, media_type="text/html")
    raise HTTPException(status_code=404, detail="SSO Portal UI not found")


@app.get("/favicon.ico")
def get_favicon():
    fav = static_dir / "favicon.ico"
    if fav.exists():
        return FileResponse(fav)
    raise HTTPException(status_code=404)


@app.get("/.well-known/jwks.json")
def get_well_known_jwks():
    return gateway_instance.get_public_keys()["jwks"]


@app.get("/api/auth/keys")
def get_api_auth_keys():
    return gateway_instance.get_public_keys()


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest):
    try:
        result = gateway_instance.register(
            username=req.username,
            password=req.password,
            email=req.email,
            display_name=req.display_name,
        )
        return result
    except ValueError as e:
        err_msg = str(e)
        if "đã được sử dụng" in err_msg or "already" in err_msg:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Registration error: {ex}")


@app.post("/api/auth/login")
def login_user(req: LoginRequest):
    ident = (req.username or req.identifier or "").strip()
    if not ident:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vui lòng cung cấp username hoặc email.")

    result = gateway_instance.authenticate(ident, req.password)
    if not result:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sai tên đăng nhập, email hoặc mật khẩu.")

    return result


@app.post("/api/auth/google")
def google_auth(req: GoogleAuthRequest):
    try:
        result = gateway_instance.google_auth(req.credential)
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Google OAuth error: {ex}")


@app.get("/api/auth/me")
def get_current_user_profile(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Yêu cầu header Authorization: Bearer <token>")

    token = authorization[len("Bearer "):].strip()
    payload = verify_universal_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không hợp lệ hoặc đã hết hạn.")

    user_id = payload.get("sub")
    user = gateway_instance.get_user_by_id(user_id) if user_id else None
    if not user:
        return {
            "status": "ok",
            "user": {
                "id": user_id,
                "username": payload.get("username"),
                "email": payload.get("email"),
                "display_name": payload.get("display_name"),
                "role": payload.get("role", "user"),
            }
        }

    return {"status": "ok", "user": user}


@app.api_route("/api/auth/verify", methods=["GET", "POST"])
def verify_token_endpoint(
    req: Optional[VerifyRequest] = None,
    token_query: Optional[str] = Query(None, alias="token"),
    authorization: Optional[str] = Header(None)
):
    token = None
    if req and req.token:
        token = req.token
    elif token_query:
        token = token_query
    elif authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):].strip()

    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vui lòng cung cấp token để xác thực.")

    payload = verify_universal_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token không hợp lệ hoặc đã hết hạn.")

    return {
        "status": "ok",
        "valid": True,
        "user": {
            "id": payload.get("sub"),
            "username": payload.get("username"),
            "email": payload.get("email"),
            "display_name": payload.get("display_name"),
            "role": payload.get("role", "user"),
            "exp": payload.get("exp"),
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Meikova Auth Gateway & Universal SSO Service")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host to bind")
    # Render sets PORT automatically (defaults to 10000 on Render, or 8990 locally)
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8990")), help="Port to bind")
    args = parser.parse_args()

    import uvicorn
    print(f"Meikova Auth Gateway starting on {args.host}:{args.port}")
    uvicorn.run("server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
