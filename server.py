# -*- coding: utf-8 -*-
"""
Meikova Auth Gateway & Universal SSO Service
Independent, Production-Ready Identity & Authentication Gateway for Render Cloud & Edge.
Connects to Turso Cloud SQLite (`meikova-auth`) and issues 30-day Ed25519 JWT tokens.
Supports Multiplatform Credential Management, Active Sessions, PATs, Dynamic Host Discovery, and App Releases.
"""

import os
import sys
import argparse
import urllib.parse
from pathlib import Path
from typing import Optional, List, Dict, Any

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
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from core.auth_gateway import AuthGateway, gateway_instance, get_google_client_id
from core.universal_sso import verify_universal_token, issue_universal_token
from core.tunnel_manager import tunnel_manager

app = FastAPI(
    title="Meikova Auth Gateway & Credential Manager",
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

# Static assets (favicons, manifests, dashboards)
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


class UpdateProfileRequest(BaseModel):
    display_name: Optional[str] = Field(None, description="New display name")
    email: Optional[str] = Field(None, description="New email address")


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=6, description="New password (minimum 6 characters)")


class CreateTokenRequest(BaseModel):
    name: str = Field(..., min_length=1, description="Token name or purpose")
    scopes: Optional[str] = Field("read,write", description="Permission scopes")
    ttl_days: Optional[int] = Field(90, ge=1, le=365, description="Token validity in days")


class TotpEnableRequest(BaseModel):
    secret: str = Field(..., description="Base32 TOTP secret")
    code: str = Field(..., min_length=6, max_length=6, description="6-digit verification code")


class TotpVerifyLoginRequest(BaseModel):
    temp_token: str = Field(..., description="Temporary 2FA token from login step")
    code: str = Field(..., description="6-digit TOTP or 8-char recovery code")


class TotpDisableRequest(BaseModel):
    password: Optional[str] = Field(None, description="Account password")
    code: Optional[str] = Field(None, description="Current 6-digit TOTP code")


class PinSetupRequest(BaseModel):
    pin: str = Field(..., min_length=6, max_length=6, description="6-digit numeric PIN")
    password: str = Field(..., description="Current account password")


class PinVerifyRequest(BaseModel):
    pin: str = Field(..., min_length=6, max_length=6, description="6-digit numeric PIN")


class PinChangeRequest(BaseModel):
    new_pin: str = Field(..., min_length=6, max_length=6, description="New 6-digit numeric PIN")
    old_pin: Optional[str] = Field(None, min_length=6, max_length=6, description="Current 6-digit numeric PIN")
    password: Optional[str] = Field(None, description="Current account password")


class PinDisableRequest(BaseModel):
    password: str = Field(..., description="Current account password")


# Helpers
def _client_telemetry(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "127.0.0.1")
    ua = request.headers.get("user-agent", "")
    device_name = "Trình duyệt Desktop" if ("Windows" in ua or "Macintosh" in ua or "Linux" in ua) else ("Thiết bị Di động" if ("Android" in ua or "iPhone" in ua) else "Web Client")
    device_type = "mobile" if ("Android" in ua or "iPhone" in ua) else "desktop"
    return ip, ua, device_name, device_type


def _require_auth_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Yêu cầu header Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = authorization[len("Bearer "):].strip()
    payload = verify_universal_token(token)
    if not payload or payload.get("scope") == "2fa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ hoặc đã hết hạn."
        )

    user_id = payload.get("sub")
    user = gateway_instance.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Không tìm thấy thông tin tài khoản.")
    return user


# Routes
@app.get("/")
def root_route(request: Request):
    accept = request.headers.get("accept", "")
    # Serve Web Credential Manager SPA if requested by browser
    if "text/html" in accept:
        dashboard_page = static_dir / "index.html"
        if dashboard_page.exists():
            return FileResponse(dashboard_page, media_type="text/html")
        sso_page = static_dir / "sso.html"
        if sso_page.exists():
            return FileResponse(sso_page, media_type="text/html")

    return {
        "service": "meikova-auth-gateway",
        "name": "Meikova Auth Gateway & Universal SSO",
        "version": "1.0.0",
        "status": "online",
        "architecture": "turso-cloud-libsql-ed25519",
        "docs_url": "/docs",
        "web_app": "/dashboard",
        "sso_portal": "/login",
        "endpoints": {
            "health": "/health",
            "register": "POST /api/auth/register",
            "login": "POST /api/auth/login",
            "google": "POST /api/auth/google",
            "me": "GET /api/auth/me",
            "profile": "PATCH /api/auth/profile",
            "password": "POST /api/auth/password",
            "sessions": "GET|DELETE /api/auth/sessions",
            "tokens": "GET|POST|DELETE /api/auth/tokens",
            "host_info": "GET /api/host-info",
            "qr": "GET /api/qr",
            "download": "GET /api/download/app/{target}",
            "verify": "GET|POST /api/auth/verify",
            "keys": "GET /api/auth/keys",
            "jwks": "GET /.well-known/jwks.json",
            "config": "GET /api/auth/config",
        }
    }


@app.get("/dashboard", response_class=FileResponse)
@app.get("/app", response_class=FileResponse)
@app.get("/account", response_class=FileResponse)
def get_dashboard_page():
    dashboard_page = static_dir / "index.html"
    if dashboard_page.exists():
        return FileResponse(dashboard_page, media_type="text/html")
    sso_page = static_dir / "sso.html"
    if sso_page.exists():
        return FileResponse(sso_page, media_type="text/html")
    raise HTTPException(status_code=404, detail="Dashboard UI not found")


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


@app.get("/api/auth/config")
@app.get("/api/auth/google/config")
def get_auth_config():
    return {
        "status": "online",
        "google_client_id": get_google_client_id(),
        "sso_portal": "/login",
        "dashboard_url": "/dashboard",
        "version": "1.0.0",
        "brand": {
            "name": "Meikova Auth",
            "accent": "#A6C5FF",
            "tagline": "Cổng Xác Thực & Quản Lý Thông Tin Danh Tính Tập Trung"
        }
    }


@app.get("/health")
@app.get("/api/health")
def health_check():
    backend = "turso" if gateway_instance.is_turso else "sqlite_local"
    db_ok = False
    try:
        row = gateway_instance.fetchone("SELECT 1")
        db_ok = row is not None and (row[0] == 1 if hasattr(row, '__getitem__') else True)
    except Exception:
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


# Network Host Discovery & QR
@app.get("/api/host-info")
@app.get("/api/network/host-info")
def get_host_info_endpoint(request: Request):
    port = int(os.environ.get("PORT", "8990"))
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or f"127.0.0.1:{port}"
    res = gateway_instance.get_host_info(host, port)
    tunnel_st = tunnel_manager.get_status()
    res["tunnel"] = tunnel_st
    if tunnel_st.get("running") and tunnel_st.get("url"):
        res["active_url"] = tunnel_st["url"]
        res["public_origin"] = tunnel_st["url"]
    return res


# Cloudflare Quick Tunnel API (Multi-Platform One-Click WAN)
@app.get("/api/tunnel/status")
def get_tunnel_status():
    return tunnel_manager.get_status()


@app.post("/api/tunnel/start")
def start_tunnel():
    port = int(os.environ.get("PORT", "8990"))
    try:
        st = tunnel_manager.start(port)
        return {"ok": True, **st}
    except Exception as e:
        st = tunnel_manager.get_status()
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e), **st})


@app.post("/api/tunnel/stop")
def stop_tunnel():
    st = tunnel_manager.stop()
    return {"ok": True, **st}


@app.post("/api/tunnel/toggle")
def toggle_tunnel():
    port = int(os.environ.get("PORT", "8990"))
    try:
        if tunnel_manager.status == "running":
            st = tunnel_manager.stop()
        else:
            st = tunnel_manager.start(port)
        return {"ok": True, **st}
    except Exception as e:
        st = tunnel_manager.get_status()
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e), **st})


@app.get("/api/qr")
def qr_endpoint(data: str = Query(...), format: Optional[str] = Query(None)):
    encoded = urllib.parse.quote(data.strip())
    # 307 Redirect to high-contrast qrserver matching dark theme
    target_url = f"https://api.qrserver.com/v1/create-qr-code/?data={encoded}&size=260x260&bgcolor=070D17&color=A6C5FF"
    return RedirectResponse(url=target_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


# Dynamic App Download Resolvers (Rule 15)
@app.get("/api/download/app/{target}")
def download_app_target(target: str):
    info = gateway_instance.resolve_app_asset(target)
    return info


# Authentication Endpoints
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest, request: Request):
    ip, ua, d_name, _ = _client_telemetry(request)
    try:
        result = gateway_instance.register(
            username=req.username,
            password=req.password,
            email=req.email,
            display_name=req.display_name,
            device_name=d_name,
            user_agent=ua,
            ip_address=ip
        )
        result["code"] = "AUTH_REGISTER_SUCCESS"
        return result
    except ValueError as e:
        err_msg = str(e)
        if "đã được sử dụng" in err_msg or "already" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"code": "AUTH_USER_ALREADY_EXISTS", "message": err_msg}
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_INVALID_REGISTRATION", "message": err_msg}
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "AUTH_INTERNAL_ERROR", "message": f"Registration error: {ex}"}
        )


@app.post("/api/auth/login")
def login_user(req: LoginRequest, request: Request):
    ident = (req.username or req.identifier or "").strip()
    if not ident:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_IDENTIFIER_REQUIRED", "message": "Vui lòng cung cấp username hoặc email."}
        )

    ip, ua, d_name, d_type = _client_telemetry(request)
    result = gateway_instance.authenticate(
        ident,
        req.password,
        device_name=d_name,
        device_type=d_type,
        user_agent=ua,
        ip_address=ip
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_INVALID_CREDENTIALS", "message": "Sai tên đăng nhập, email hoặc mật khẩu."}
        )

    if result.get("require_totp"):
        result["code"] = "AUTH_REQUIRE_TOTP"
    else:
        result["code"] = "AUTH_LOGIN_SUCCESS"
    return result


@app.post("/api/auth/google")
def google_auth(req: GoogleAuthRequest, request: Request):
    ip, ua, d_name, _ = _client_telemetry(request)
    try:
        result = gateway_instance.google_auth(
            req.credential,
            device_name=d_name,
            user_agent=ua,
            ip_address=ip
        )
        result["code"] = "AUTH_GOOGLE_SUCCESS"
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_GOOGLE_INVALID", "message": str(e)}
        )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "AUTH_INTERNAL_ERROR", "message": f"Google OAuth error: {ex}"}
        )


@app.get("/api/auth/me")
def get_current_user_profile(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Yêu cầu header Authorization: Bearer <token>"
        )

    token = authorization[len("Bearer "):].strip()
    payload = verify_universal_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ hoặc đã hết hạn."
        )

    user_id = payload.get("sub")
    user = gateway_instance.get_user_by_id(user_id) if user_id else None
    if not user:
        return {
            "status": "ok",
            "code": "AUTH_USER_RETRIEVED",
            "user": {
                "id": user_id,
                "username": payload.get("username"),
                "email": payload.get("email"),
                "display_name": payload.get("display_name"),
                "role": payload.get("role", "user"),
            }
        }

    return {"status": "ok", "code": "AUTH_USER_RETRIEVED", "user": user}


# Credential Management Endpoints
@app.patch("/api/auth/profile")
def update_profile_endpoint(req: UpdateProfileRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        updated = gateway_instance.update_profile(
            user_id=user["id"],
            display_name=req.display_name,
            email=req.email
        )
        return {
            "success": True,
            "status": "ok",
            "code": "AUTH_PROFILE_UPDATED",
            "message": "Cập nhật thông tin hồ sơ thành công.",
            "user": updated
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_PROFILE_UPDATE_FAILED", "message": str(e)}
        )


@app.post("/api/auth/password")
def change_password_endpoint(
    req: ChangePasswordRequest,
    request: Request,
    authorization: Optional[str] = Header(None)
):
    user = _require_auth_user(authorization)
    ip, ua, _, _ = _client_telemetry(request)
    try:
        gateway_instance.change_password(
            user_id=user["id"],
            old_password=req.old_password,
            new_password=req.new_password,
            ip_address=ip,
            user_agent=ua
        )
        return {
            "success": True,
            "status": "ok",
            "code": "AUTH_PASSWORD_CHANGED",
            "message": "Đổi mật khẩu tài khoản thành công."
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_PASSWORD_CHANGE_FAILED", "message": str(e)}
        )


@app.get("/api/auth/sessions")
def get_user_sessions_endpoint(authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    sessions = gateway_instance.get_sessions(user["id"])
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_SESSIONS_RETRIEVED",
        "count": len(sessions),
        "sessions": sessions
    }


@app.delete("/api/auth/sessions/{session_id}")
def revoke_session_endpoint(session_id: str, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    gateway_instance.revoke_session(user["id"], session_id)
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_SESSION_REVOKED",
        "session_id": session_id,
        "message": "Đã thu hồi phiên đăng nhập thành công."
    }


@app.post("/api/auth/sessions/revoke-others")
def revoke_other_sessions_endpoint(
    current_session_id: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None)
):
    user = _require_auth_user(authorization)
    gateway_instance.revoke_other_sessions(user["id"], current_session_id)
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_ALL_SESSIONS_REVOKED",
        "message": "Đã đăng xuất khỏi tất cả các thiết bị khác thành công."
    }


@app.get("/api/auth/identities")
def get_identities_endpoint(authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    identities = gateway_instance.get_identities(user["id"])
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_IDENTITIES_RETRIEVED",
        "identities": identities
    }


@app.get("/api/auth/apps")
def get_ecosystem_apps_endpoint(authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    apps = gateway_instance.get_authorized_apps(user["id"])
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_APPS_RETRIEVED",
        "apps": apps
    }


@app.get("/api/auth/tokens")
def get_tokens_endpoint(authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    pats = gateway_instance.get_pats(user["id"])
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_TOKENS_RETRIEVED",
        "tokens": pats
    }


@app.post("/api/auth/tokens", status_code=status.HTTP_201_CREATED)
def create_token_endpoint(req: CreateTokenRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    token_data = gateway_instance.create_pat(
        user_id=user["id"],
        name=req.name,
        scopes=req.scopes or "read,write",
        ttl_days=req.ttl_days or 90
    )
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_TOKEN_CREATED",
        "message": "Tạo Personal Access Token thành công.",
        "token": token_data
    }


@app.delete("/api/auth/tokens/{token_id}")
def revoke_token_endpoint(token_id: str, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    gateway_instance.revoke_pat(user["id"], token_id)
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_TOKEN_REVOKED",
        "token_id": token_id,
        "message": "Đã thu hồi token thành công."
    }


@app.get("/api/auth/audit")
def get_audit_endpoint(limit: int = Query(20, ge=1, le=100), authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    logs = gateway_instance.get_audit_logs(user["id"], limit=limit)
    return {
        "success": True,
        "status": "ok",
        "code": "AUTH_AUDIT_RETRIEVED",
        "logs": logs
    }


# === 2FA TOTP Endpoints ===

@app.post("/api/auth/totp/setup")
def setup_totp_endpoint(authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        data = gateway_instance.setup_totp(user["id"])
        data["code"] = "AUTH_TOTP_SETUP_SUCCESS"
        data["qr_url"] = f"/api/qr?data={urllib.parse.quote(data['otpauth_url'])}"
        return data
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_TOTP_SETUP_FAILED", "message": str(ex)}
        )


@app.post("/api/auth/totp/enable")
def enable_totp_endpoint(req: TotpEnableRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        data = gateway_instance.enable_totp(user["id"], req.secret, req.code)
        data["code"] = "AUTH_TOTP_ENABLED"
        return data
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_TOTP_INVALID", "message": str(ex)}
        )


@app.post("/api/auth/totp/verify")
def verify_totp_login_endpoint(req: TotpVerifyLoginRequest, request: Request):
    payload = verify_universal_token(req.temp_token)
    if not payload or payload.get("scope") != "2fa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_TOKEN_EXPIRED", "message": "Phiên 2FA đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại."}
        )

    user_id = payload.get("sub")
    ip, ua, d_name, d_type = _client_telemetry(request)
    try:
        result = gateway_instance.verify_totp_login(
            user_id=user_id,
            code=req.code,
            device_name=d_name,
            device_type=d_type,
            user_agent=ua,
            ip_address=ip
        )
        result["code"] = "AUTH_LOGIN_SUCCESS"
        return result
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_TOTP_INVALID", "message": str(ex)}
        )


@app.post("/api/auth/totp/disable")
def disable_totp_endpoint(req: TotpDisableRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        gateway_instance.disable_totp(user["id"], password=req.password, code=req.code)
        return {"code": "AUTH_TOTP_DISABLED", "success": True}
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_DISABLE_FAILED", "message": str(ex)}
        )


# === Security PIN Endpoints ===

@app.post("/api/auth/pin/setup")
def setup_pin_endpoint(req: PinSetupRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        gateway_instance.setup_pin(user["id"], req.pin, req.password)
        return {"code": "AUTH_PIN_SETUP_SUCCESS", "success": True}
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_PIN_INVALID", "message": str(ex)}
        )


@app.post("/api/auth/pin/verify")
def verify_pin_endpoint(req: PinVerifyRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        gateway_instance.verify_pin(user["id"], req.pin)
        return {"code": "AUTH_PIN_VERIFIED", "success": True, "verified": True}
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_PIN_INVALID", "message": str(ex)}
        )


@app.post("/api/auth/pin/change")
def change_pin_endpoint(req: PinChangeRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        gateway_instance.change_pin(user["id"], req.new_pin, old_pin=req.old_pin, password=req.password)
        return {"code": "AUTH_PIN_CHANGED", "success": True}
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_PIN_CHANGE_FAILED", "message": str(ex)}
        )


@app.post("/api/auth/pin/disable")
def disable_pin_endpoint(req: PinDisableRequest, authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    try:
        gateway_instance.disable_pin(user["id"], req.password)
        return {"code": "AUTH_PIN_DISABLED", "success": True}
    except ValueError as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_PIN_DISABLE_FAILED", "message": str(ex)}
        )


@app.get("/api/auth/security/status")
def security_status_endpoint(authorization: Optional[str] = Header(None)):
    user = _require_auth_user(authorization)
    status_data = gateway_instance.get_security_status(user["id"])
    status_data["code"] = "AUTH_SECURITY_STATUS"
    return status_data


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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vui lòng cung cấp token để xác thực."
        )

    payload = verify_universal_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token không hợp lệ hoặc đã hết hạn."
        )

    return {
        "status": "ok",
        "code": "AUTH_TOKEN_VALID",
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


@app.on_event("startup")
def on_app_startup():
    if "--tunnel" in sys.argv or os.environ.get("AUTO_TUNNEL") in ("1", "true", "True"):
        port = int(os.environ.get("PORT", "8990"))
        def _auto_tunnel():
            time.sleep(1.0)
            try:
                st = tunnel_manager.start(port)
                print(f"[Tunnel] Active URL: {st.get('url')}")
            except Exception as e:
                print(f"[Tunnel] Auto-start failed: {e}")
        threading.Thread(target=_auto_tunnel, daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description="Meikova Auth Gateway & Universal SSO Service")
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"), help="Host to bind")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8990")), help="Port to bind")
    parser.add_argument("--tunnel", action="store_true", help="Auto-start Cloudflare Quick Tunnel")
    args = parser.parse_args()

    if args.tunnel:
        os.environ["AUTO_TUNNEL"] = "1"

    import uvicorn
    print(f"Meikova Auth Gateway starting on {args.host}:{args.port}")
    uvicorn.run("server:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
