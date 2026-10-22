# -*- coding: utf-8 -*-
"""
Meikova Auth Gateway — Core Database & Authentication Layer
Supports:
- Turso Cloud SQLite (`meikova-auth`) over encrypted HTTPS/libSQL pipeline.
- Local SQLite WAL fallback at `data/meikova_auth_local.db` when offline.
- PBKDF2-SHA256 password hashing (100,000 iterations).
- 1-Click Google OAuth Identity linking and auto-provisioning.
- RFC 8037 standard JWKS export for zero-roundtrip offline verification.
"""

import os
import uuid
import time
import json
import sqlite3
import hashlib
import secrets
import base64
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, Dict, Any, List

from .universal_sso import issue_universal_token, verify_universal_token, DEFAULT_PUB_KEY

CORE_DIR = Path(__file__).resolve().parent
AUTH_ROOT = CORE_DIR.parent
DATA_DIR = AUTH_ROOT / "data"

AUTH_TURSO_URL = os.environ.get(
    "AUTH_TURSO_DATABASE_URL",
    os.environ.get("TURSO_AUTH_DB_URL", "https://meikova-auth-m3ik18dp.aws-ap-northeast-1.turso.io")
).strip()
if AUTH_TURSO_URL.startswith("libsql://"):
    AUTH_TURSO_URL = "https://" + AUTH_TURSO_URL[len("libsql://"):]

AUTH_TURSO_TOKEN = os.environ.get(
    "AUTH_TURSO_AUTH_TOKEN",
    os.environ.get(
        "TURSO_AUTH_DB_TOKEN",
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3OTI1ODkwOTEsImlkIjoiMDFhMTVlYTItYjYwMS03YWY5LWJkNmUtNzBiZTgwY2Q2NjRlIiwia2lkIjoibk13eDJZSGtEaHVvYl81SXZkM1FQVzhpVi1ZT0poeHdUbmpIMXo5dl9iMCIsInJpZCI6IjFmZjUxMDBkLTRiYzMtNGQ5MC05NDFjLTI5ODgzNDRmNzk3MiJ9.jMF58ksAGJvsG1KTlt_R3Yb4VElcERo01KsrEHIpVm5B7d5OVXnZq5iyA6nf7tJwTiSh3_ZPPBIqdaOufipIAQ"
    )
).strip()

LOCAL_AUTH_DB = DATA_DIR / "meikova_auth_local.db"


def get_google_client_id() -> str:
    """3-Tier Fallback: 1. os.environ -> 2. client_secret.json -> 3. Standard SSOT default."""
    env_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    if env_id:
        return env_id
    secret_file = AUTH_ROOT / "client_secret.json"
    if secret_file.exists():
        try:
            data = json.loads(secret_file.read_text(encoding="utf-8"))
            web = data.get("web") or data.get("installed") or {}
            cid = web.get("client_id", "").strip()
            if cid:
                return cid
        except Exception:
            pass
    return "515668723869-5g65hqgjvubafrqjcgdlb4jbsjcbe531.apps.googleusercontent.com"


def get_google_client_secret() -> str:
    """3-Tier Fallback: 1. os.environ -> 2. client_secret.json -> 3. Empty."""
    env_sec = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    if env_sec:
        return env_sec
    secret_file = AUTH_ROOT / "client_secret.json"
    if secret_file.exists():
        try:
            data = json.loads(secret_file.read_text(encoding="utf-8"))
            web = data.get("web") or data.get("installed") or {}
            sec = web.get("client_secret", "").strip()
            if sec:
                return sec
        except Exception:
            pass
    return ""


class AuthGateway:
    def __init__(self, turso_url: str = AUTH_TURSO_URL, turso_token: str = AUTH_TURSO_TOKEN, local_db_path: Path = LOCAL_AUTH_DB):
        self.turso_url = turso_url
        self.turso_token = turso_token
        self.local_db_path = local_db_path
        self.is_turso = bool(self.turso_url and self.turso_token)
        self._init_local_schema()

    def _init_local_schema(self):
        parent_dir = self.local_db_path.parent
        if parent_dir:
            os.makedirs(str(parent_dir), exist_ok=True)

        conn = sqlite3.connect(str(self.local_db_path), timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    salt TEXT,
                    display_name TEXT,
                    avatar_url TEXT,
                    role TEXT DEFAULT 'user',
                    status TEXT DEFAULT 'active',
                    created_at INTEGER,
                    updated_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS identities (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    provider_user_id TEXT NOT NULL,
                    email TEXT,
                    created_at INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(provider, provider_user_id)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    refresh_token_hash TEXT,
                    device_name TEXT,
                    device_type TEXT,
                    user_agent TEXT,
                    ip_address TEXT,
                    created_at INTEGER,
                    expires_at INTEGER,
                    revoked_at INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS app_authorizations (
                    user_id TEXT NOT NULL,
                    app_id TEXT NOT NULL,
                    scopes TEXT,
                    authorized_at INTEGER,
                    PRIMARY KEY (user_id, app_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_turso_client(self):
        import libsql_client
        return libsql_client.create_client_sync(self.turso_url, auth_token=self.turso_token)

    def execute(self, sql: str, params: tuple = ()):
        if self.is_turso:
            try:
                with self._get_turso_client() as client:
                    res = client.execute(sql, list(params) if isinstance(params, tuple) else params)
                    return res.rows
            except Exception as e:
                print(f"[Turso Auth Error] {e}, falling back to local SQLite")

        conn = sqlite3.connect(str(self.local_db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            cur = conn.cursor()
            cur.execute(sql, params)
            conn.commit()
            return cur.fetchall()
        finally:
            conn.close()

    def fetchone(self, sql: str, params: tuple = ()):
        rows = self.execute(sql, params)
        return rows[0] if rows else None

    @staticmethod
    def _row_val(row: Any, key: str, index: int, default: Any = None) -> Any:
        if row is None:
            return default
        if hasattr(row, "__getitem__"):
            try:
                val = row[key]
                if val is not None:
                    return val
            except Exception:
                pass
            try:
                return row[index]
            except Exception:
                pass
        return default

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        pwd_bytes = password.encode("utf-8")
        salt_bytes = bytes.fromhex(salt)
        return hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100_000).hex()

    def register(self, username: str, password: str, email: Optional[str] = None, display_name: Optional[str] = None) -> Dict[str, Any]:
        clean_user = str(username or "").strip().lower()
        if not clean_user or len(clean_user) < 3:
            raise ValueError("Tên đăng nhập phải có ít nhất 3 ký tự.")
        if not password or len(password) < 6:
            raise ValueError("Mật khẩu phải có ít nhất 6 ký tự.")

        clean_email = str(email or "").strip().lower() if email else None
        clean_name = str(display_name or "").strip() or clean_user

        existing = self.fetchone(
            "SELECT id FROM users WHERE LOWER(username) = ? OR (email IS NOT NULL AND LOWER(email) = ?)",
            (clean_user, clean_email or "")
        )
        if existing:
            raise ValueError("Tên đăng nhập hoặc email đã được sử dụng trong hệ sinh thái Meikova.")

        user_id = f"usr_{uuid.uuid4().hex[:16]}"
        salt = secrets.token_hex(16)
        pwd_hash = self.hash_password(password, salt)
        now = int(time.time())

        self.execute(
            "INSERT INTO users (id, email, username, password_hash, salt, display_name, role, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'user', 'active', ?, ?)",
            (user_id, clean_email, clean_user, pwd_hash, salt, clean_name, now, now)
        )

        sso_token = issue_universal_token(
            user_id=user_id,
            username=clean_user,
            email=clean_email,
            display_name=clean_name,
            role="user"
        )

        return {
            "status": "ok",
            "token": sso_token,
            "user": {
                "id": user_id,
                "username": clean_user,
                "email": clean_email,
                "display_name": clean_name,
                "role": "user"
            }
        }

    def authenticate(self, identifier: str, password: str) -> Optional[Dict[str, Any]]:
        clean_id = str(identifier or "").strip().lower()
        if not clean_id or not password:
            return None

        row = self.fetchone(
            "SELECT id, username, email, display_name, password_hash, salt, role FROM users "
            "WHERE LOWER(username) = ? OR LOWER(email) = ?",
            (clean_id, clean_id)
        )
        if not row:
            return None

        user_id = self._row_val(row, "id", 0)
        username = self._row_val(row, "username", 1)
        email = self._row_val(row, "email", 2)
        display_name = self._row_val(row, "display_name", 3)
        expected_hash = self._row_val(row, "password_hash", 4)
        salt = self._row_val(row, "salt", 5)
        role = self._row_val(row, "role", 6) or "user"

        calc_hash = self.hash_password(password, salt)
        if not secrets.compare_digest(expected_hash, calc_hash):
            return None

        sso_token = issue_universal_token(
            user_id=user_id,
            username=username,
            email=email,
            display_name=display_name or username,
            role=role
        )

        return {
            "status": "ok",
            "token": sso_token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "display_name": display_name or username,
                "role": role
            }
        }

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        row = self.fetchone(
            "SELECT id, email, username, display_name, avatar_url, role, status, created_at FROM users WHERE id = ?",
            (user_id,)
        )
        if not row:
            return None
        return {
            "id": self._row_val(row, "id", 0),
            "email": self._row_val(row, "email", 1),
            "username": self._row_val(row, "username", 2),
            "display_name": self._row_val(row, "display_name", 3) or self._row_val(row, "username", 2),
            "avatar_url": self._row_val(row, "avatar_url", 4),
            "role": self._row_val(row, "role", 5) or "user",
            "status": self._row_val(row, "status", 6) or "active",
            "created_at": self._row_val(row, "created_at", 7),
        }

    @staticmethod
    def verify_google_credential(credential: str) -> Optional[Dict[str, Any]]:
        if not credential:
            return None

        # 1. Online validation via Google tokeninfo
        try:
            url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(credential)}"
            req = urllib.request.Request(url, headers={"User-Agent": "MeikovaAuthGateway"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    email = data.get("email")
                    if email:
                        return {
                            "email": email.strip().lower(),
                            "name": data.get("name") or email.split("@")[0],
                            "sub": data.get("sub") or email,
                            "picture": data.get("picture"),
                        }
        except Exception:
            pass

        # 2. Local JWT payload extraction
        try:
            parts = credential.strip().split(".")
            if len(parts) >= 2:
                payload_raw = parts[1]
                rem = len(payload_raw) % 4
                if rem:
                    payload_raw += "=" * (4 - rem)
                payload_json = base64.urlsafe_b64decode(payload_raw).decode("utf-8")
                payload = json.loads(payload_json)
                email = payload.get("email")
                if email:
                    return {
                        "email": email.strip().lower(),
                        "name": payload.get("name") or email.split("@")[0],
                        "sub": payload.get("sub") or email,
                        "picture": payload.get("picture"),
                    }
        except Exception:
            pass

        return None

    def google_auth(self, credential: str) -> Dict[str, Any]:
        g_info = self.verify_google_credential(credential)
        if not g_info or not g_info.get("email"):
            raise ValueError("Google ID Token không hợp lệ hoặc đã hết hạn.")

        email = g_info["email"]
        disp_name = g_info.get("name") or email.split("@")[0]
        google_sub = str(g_info.get("sub") or email)
        avatar_url = g_info.get("picture")
        now = int(time.time())

        # Check existing identity
        id_row = self.fetchone(
            "SELECT user_id FROM identities WHERE provider = 'google' AND provider_user_id = ?",
            (google_sub,)
        )
        if id_row:
            user_id = self._row_val(id_row, "user_id", 0)
            user_data = self.get_user_by_id(user_id)
            if user_data:
                token = issue_universal_token(
                    user_id=user_data["id"],
                    username=user_data["username"],
                    email=user_data.get("email"),
                    display_name=user_data.get("display_name"),
                    role=user_data.get("role", "user")
                )
                return {"status": "ok", "token": token, "user": user_data}

        # Check existing user by email
        user_row = self.fetchone("SELECT id, username, display_name, role FROM users WHERE LOWER(email) = ?", (email,))
        if user_row:
            user_id = self._row_val(user_row, "id", 0)
            username = self._row_val(user_row, "username", 1)
            display_name = self._row_val(user_row, "display_name", 2) or username
            role = self._row_val(user_row, "role", 3) or "user"

            # Link Google identity
            identity_id = f"ident_{uuid.uuid4().hex[:16]}"
            self.execute(
                "INSERT INTO identities (id, user_id, provider, provider_user_id, email, created_at) VALUES (?, ?, 'google', ?, ?, ?)",
                (identity_id, user_id, google_sub, email, now)
            )

            token = issue_universal_token(user_id=user_id, username=username, email=email, display_name=display_name, role=role)
            return {
                "status": "ok",
                "token": token,
                "user": {"id": user_id, "username": username, "email": email, "display_name": display_name, "role": role}
            }

        # Provision new user
        user_id = f"usr_{uuid.uuid4().hex[:16]}"
        base_username = email.split("@")[0].lower()
        candidate_username = base_username

        suffix = 1
        while self.fetchone("SELECT id FROM users WHERE LOWER(username) = ?", (candidate_username,)):
            candidate_username = f"{base_username}_{suffix}"
            suffix += 1

        self.execute(
            "INSERT INTO users (id, email, username, display_name, avatar_url, role, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 'user', 'active', ?, ?)",
            (user_id, email, candidate_username, disp_name, avatar_url, now, now)
        )

        identity_id = f"ident_{uuid.uuid4().hex[:16]}"
        self.execute(
            "INSERT INTO identities (id, user_id, provider, provider_user_id, email, created_at) VALUES (?, ?, 'google', ?, ?, ?)",
            (identity_id, user_id, google_sub, email, now)
        )

        token = issue_universal_token(user_id=user_id, username=candidate_username, email=email, display_name=disp_name, role="user")
        return {
            "status": "ok",
            "token": token,
            "user": {
                "id": user_id,
                "username": candidate_username,
                "email": email,
                "display_name": disp_name,
                "avatar_url": avatar_url,
                "role": "user"
            }
        }

    @staticmethod
    def get_public_keys() -> Dict[str, Any]:
        from .universal_sso import sso_instance
        pub_pem = sso_instance.public_key_pem or ""

        # RFC 8037 JWKS for Ed25519
        jwks_key = {"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA"}
        try:
            from cryptography.hazmat.primitives import serialization
            pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            jwks_key["x"] = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        except Exception:
            pass

        return {
            "algorithm": "Ed25519",
            "format": "PEM",
            "public_key_pem": pub_pem,
            "jwks": {"keys": [jwks_key]}
        }


gateway_instance = AuthGateway()
