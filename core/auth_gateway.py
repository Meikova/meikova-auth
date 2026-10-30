# -*- coding: utf-8 -*-
"""
Meikova Auth Gateway — Core Database & Authentication Layer
Supports:
- Turso Cloud SQLite (`meikova-auth`) over encrypted HTTPS/libSQL pipeline.
- Local SQLite WAL fallback at `data/meikova_auth_local.db` when offline.
- PBKDF2-SHA256 password hashing (600,000 iterations according to OWASP / Meikova standard, with 100k legacy verification).
- 1-Click Google OAuth Identity linking and auto-provisioning.
- RFC 8037 standard JWKS export for zero-roundtrip offline verification.
- Active Sessions & Device telemetry tracking and revocation.
- Personal Access Tokens (PAT) / API Key management.
- Dynamic Host Discovery (Tailscale IP, LAN IP, Active URL) according to Rule 18.
- Dynamic Release Asset Resolver according to Rule 15.
"""

import os
import uuid
import time
import json
import sqlite3
import hashlib
import hmac
import secrets
import base64
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, Dict, Any, List

from .universal_sso import issue_universal_token, verify_universal_token, DEFAULT_PUB_KEY
from .security_shield import strike_tracker, dummy_pbkdf2_hash

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


def generate_totp_secret() -> str:
    """Sinh chuỗi secret ngẫu nhiên 160-bit (20 bytes) mã hóa Base32 cho TOTP RFC 6238."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def generate_totp_code(secret_b32: str, for_time: Optional[int] = None, digits: int = 6) -> str:
    """Tính toán mã TOTP 6 chữ số theo chuẩn RFC 6238 dùng HMAC-SHA1 thuần Python stdlib."""
    if for_time is None:
        for_time = int(time.time())
    clean_secret = secret_b32.strip().upper()
    key = base64.b32decode(clean_secret + "=" * ((8 - len(clean_secret) % 8) % 8), casefold=True)
    counter = for_time // 30
    msg = counter.to_bytes(8, byteorder="big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp_code(secret_b32: str, code: str, window: int = 1) -> bool:
    """Xác thực mã TOTP 6 số với cửa sổ dung sai trôi đồng hồ ±window (30s)."""
    if not code or not secret_b32:
        return False
    clean_code = str(code).strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    current_time = int(time.time())
    for delta in range(-window, window + 1):
        t = current_time + (delta * 30)
        expected = generate_totp_code(secret_b32, for_time=t)
        if hmac.compare_digest(clean_code, expected):
            return True
    return False


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
                    updated_at INTEGER,
                    totp_secret TEXT,
                    totp_enabled INTEGER DEFAULT 0,
                    totp_backup_codes TEXT,
                    pin_hash TEXT,
                    pin_salt TEXT,
                    pin_enabled INTEGER DEFAULT 0
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

                CREATE TABLE IF NOT EXISTS personal_access_tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    token_prefix TEXT NOT NULL,
                    scopes TEXT DEFAULT 'read,write',
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER,
                    last_used_at INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
            """)

            for col, ctype in [
                ("totp_secret", "TEXT"),
                ("totp_enabled", "INTEGER DEFAULT 0"),
                ("totp_backup_codes", "TEXT"),
                ("pin_hash", "TEXT"),
                ("pin_salt", "TEXT"),
                ("pin_enabled", "INTEGER DEFAULT 0"),
            ]:
                try:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ctype}")
                except Exception:
                    pass

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
    def hash_password(password: str, salt: str, iterations: int = 600_000) -> str:
        pwd_bytes = password.encode("utf-8")
        salt_bytes = bytes.fromhex(salt)
        return hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, iterations).hex()

    @staticmethod
    def verify_password_hash(password: str, salt: str, stored_hash: str) -> bool:
        if not stored_hash or not salt:
            return False
        # 1. Standard 600,000 iterations (OWASP 2023 / Meikova standard)
        calc_600k = AuthGateway.hash_password(password, salt, 600_000)
        if secrets.compare_digest(stored_hash, calc_600k):
            return True
        # 2. Legacy 100,000 iterations backward-compatibility
        calc_100k = AuthGateway.hash_password(password, salt, 100_000)
        return secrets.compare_digest(stored_hash, calc_100k)

    def register(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        device_name: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        clean_user = str(username or "").strip().lower()
        if not clean_user or len(clean_user) < 3:
            raise ValueError("Tên đăng nhập phải có ít nhất 3 ký tự.")
        if not password or len(password) < 6:
            raise ValueError("Mật khẩu phải có ít nhất 6 ký tự.")

        clean_email = str(email or "").strip().lower() if email else f"{clean_user}@meikova.io"
        clean_name = str(display_name or "").strip() or clean_user

        existing = self.fetchone(
            "SELECT id FROM users WHERE LOWER(username) = ? OR (email IS NOT NULL AND LOWER(email) = ?)",
            (clean_user, clean_email or "")
        )
        if existing:
            raise ValueError("Tên đăng nhập hoặc email đã được sử dụng trong hệ sinh thái Meikova.")

        user_id = f"usr_{uuid.uuid4().hex[:16]}"
        salt = secrets.token_hex(16)
        pwd_hash = self.hash_password(password, salt, 600_000)
        now = int(time.time())

        self.execute(
            "INSERT INTO users (id, email, username, password_hash, salt, display_name, role, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'user', 'active', ?, ?)",
            (user_id, clean_email, clean_user, pwd_hash, salt, clean_name, now, now)
        )

        session_id = self.create_session(
            user_id=user_id,
            device_name=device_name or "Trình duyệt Web",
            device_type="web",
            user_agent=user_agent,
            ip_address=ip_address
        )

        sso_token = issue_universal_token(
            user_id=user_id,
            username=clean_user,
            email=clean_email,
            display_name=clean_name,
            role="user"
        )

        self.log_audit(user_id, "AUTH_REGISTER", ip_address=ip_address, user_agent=user_agent)

        return {
            "status": "ok",
            "token": sso_token,
            "session_id": session_id,
            "user": {
                "id": user_id,
                "username": clean_user,
                "email": clean_email,
                "display_name": clean_name,
                "role": "user"
            }
        }

    def authenticate(
        self,
        identifier: str,
        password: str,
        device_name: Optional[str] = None,
        device_type: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        clean_id = str(identifier or "").strip().lower()
        if not clean_id or not password:
            return None

        # Check brute-force lockout on IP and identifier
        ip_key = f"login_ip:{ip_address or '127.0.0.1'}"
        user_key = f"login_user:{clean_id}"

        ip_locked, _, ip_retry = strike_tracker.check_lock(ip_key)
        user_locked, _, user_retry = strike_tracker.check_lock(user_key)
        if ip_locked or user_locked:
            retry_sec = max(ip_retry, user_retry)
            raise ValueError(f"AUTH_RATE_LIMITED:{retry_sec}")

        row = self.fetchone(
            "SELECT id, username, email, display_name, password_hash, salt, role, totp_enabled FROM users "
            "WHERE LOWER(username) = ? OR LOWER(email) = ?",
            (clean_id, clean_id)
        )
        if not row:
            # Timing Equalizer: Run dummy PBKDF2 600,000 rounds
            dummy_pbkdf2_hash(password)
            delay = strike_tracker.get_artificial_delay(ip_key)
            if delay > 0:
                time.sleep(delay)
            strike_tracker.record_failure(ip_key)
            strike_tracker.record_failure(user_key)
            return None

        user_id = self._row_val(row, "id", 0)
        username = self._row_val(row, "username", 1)
        email = self._row_val(row, "email", 2)
        display_name = self._row_val(row, "display_name", 3)
        expected_hash = self._row_val(row, "password_hash", 4)
        salt = self._row_val(row, "salt", 5)
        role = self._row_val(row, "role", 6) or "user"
        totp_enabled = bool(self._row_val(row, "totp_enabled", 7, 0))

        if not self.verify_password_hash(password, salt, expected_hash):
            delay = strike_tracker.get_artificial_delay(ip_key)
            if delay > 0:
                time.sleep(delay)
            is_locked, strikes, retry_sec = strike_tracker.record_failure(user_key)
            strike_tracker.record_failure(ip_key)
            if is_locked:
                self.log_audit(user_id, "SECURITY_ALERT_ACCOUNT_LOCKED", ip_address=ip_address, user_agent=user_agent)
                raise ValueError(f"AUTH_RATE_LIMITED:{retry_sec}")
            return None

        # Reset login strikes on successful credential verification
        strike_tracker.record_success(ip_key)
        strike_tracker.record_success(user_key)

        if totp_enabled:
            temp_token = issue_universal_token(
                user_id=user_id,
                username=username,
                email=email,
                display_name=display_name or username,
                role=role,
                expires_in_sec=300,
                scope="2fa_pending"
            )
            return {
                "status": "require_totp",
                "require_totp": True,
                "temp_token": temp_token,
                "user": {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "display_name": display_name or username,
                    "role": role
                }
            }

        session_id = self.create_session(
            user_id=user_id,
            device_name=device_name or "Trình duyệt Web",
            device_type=device_type or "web",
            user_agent=user_agent,
            ip_address=ip_address
        )

        sso_token = issue_universal_token(
            user_id=user_id,
            username=username,
            email=email,
            display_name=display_name or username,
            role=role
        )

        self.log_audit(user_id, "AUTH_LOGIN", ip_address=ip_address, user_agent=user_agent, details={"session_id": session_id})

        return {
            "status": "ok",
            "token": sso_token,
            "session_id": session_id,
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
            "SELECT id, email, username, display_name, avatar_url, role, status, created_at, totp_enabled, pin_enabled FROM users WHERE id = ?",
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
            "totp_enabled": bool(self._row_val(row, "totp_enabled", 8, 0)),
            "pin_enabled": bool(self._row_val(row, "pin_enabled", 9, 0)),
        }

    def update_profile(self, user_id: str, display_name: Optional[str] = None, email: Optional[str] = None) -> Dict[str, Any]:
        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError("Không tìm thấy người dùng.")

        clean_name = str(display_name).strip() if display_name is not None else user.get("display_name")
        clean_email = str(email).strip().lower() if email is not None else user.get("email")

        if clean_email and clean_email != (user.get("email") or "").lower():
            existing = self.fetchone(
                "SELECT id FROM users WHERE LOWER(email) = ? AND id != ?",
                (clean_email, user_id)
            )
            if existing:
                raise ValueError("Email này đã được sử dụng bởi tài khoản khác.")

        now = int(time.time())
        self.execute(
            "UPDATE users SET display_name = ?, email = ?, updated_at = ? WHERE id = ?",
            (clean_name, clean_email, now, user_id)
        )
        self.log_audit(user_id, "AUTH_PROFILE_UPDATE", details={"display_name": clean_name, "email": clean_email})
        return self.get_user_by_id(user_id)

    def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        row = self.fetchone("SELECT id, password_hash, salt FROM users WHERE id = ?", (user_id,))
        if not row:
            raise ValueError("Không tìm thấy người dùng.")

        stored_hash = self._row_val(row, "password_hash", 1)
        salt = self._row_val(row, "salt", 2)

        if not stored_hash or not salt:
            raise ValueError("Tài khoản chưa thiết lập mật khẩu (đăng nhập qua Google).")

        if not self.verify_password_hash(old_password, salt, stored_hash):
            raise ValueError("Mật khẩu hiện tại không chính xác.")

        clean_new = str(new_password or "").strip()
        if len(clean_new) < 6:
            raise ValueError("Mật khẩu mới phải có tối thiểu 6 ký tự.")

        new_salt = secrets.token_hex(16)
        new_hash = self.hash_password(clean_new, new_salt, 600_000)
        now = int(time.time())

        self.execute(
            "UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE id = ?",
            (new_hash, new_salt, now, user_id)
        )
        self.log_audit(user_id, "AUTH_PASSWORD_CHANGE", ip_address=ip_address, user_agent=user_agent)
        return True

    def create_session(
        self,
        user_id: str,
        device_name: Optional[str] = None,
        device_type: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        ttl_days: int = 30
    ) -> str:
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        now = int(time.time())
        expires_at = now + (ttl_days * 86400)
        d_name = device_name or "Thiết bị không xác định"
        d_type = device_type or "web"
        u_agent = (user_agent or "")[:255]
        ip = (ip_address or "127.0.0.1")[:45]

        refresh_hash = hashlib.sha256((session_id + secrets.token_hex(8)).encode("utf-8")).hexdigest()
        self.execute(
            "INSERT INTO sessions (id, user_id, refresh_token_hash, device_name, device_type, user_agent, ip_address, created_at, expires_at, revoked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            (session_id, user_id, refresh_hash, d_name, d_type, u_agent, ip, now, expires_at)
        )
        return session_id

    def get_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        now = int(time.time())
        rows = self.execute(
            "SELECT id, device_name, device_type, user_agent, ip_address, created_at, expires_at, revoked_at "
            "FROM sessions WHERE user_id = ? AND (revoked_at IS NULL OR revoked_at = 0) AND expires_at > ? "
            "ORDER BY created_at DESC",
            (user_id, now)
        )
        sessions = []
        for r in (rows or []):
            sessions.append({
                "id": self._row_val(r, "id", 0),
                "device_name": self._row_val(r, "device_name", 1) or "Thiết bị",
                "device_type": self._row_val(r, "device_type", 2) or "web",
                "user_agent": self._row_val(r, "user_agent", 3) or "",
                "ip_address": self._row_val(r, "ip_address", 4) or "127.0.0.1",
                "created_at": self._row_val(r, "created_at", 5),
                "expires_at": self._row_val(r, "expires_at", 6),
            })
        return sessions

    def revoke_session(self, user_id: str, session_id: str) -> bool:
        now = int(time.time())
        self.execute(
            "UPDATE sessions SET revoked_at = ? WHERE id = ? AND user_id = ?",
            (now, session_id, user_id)
        )
        self.log_audit(user_id, "AUTH_SESSION_REVOKE", details={"session_id": session_id})
        return True

    def revoke_other_sessions(self, user_id: str, keep_session_id: Optional[str] = None) -> bool:
        now = int(time.time())
        if keep_session_id:
            self.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND (revoked_at IS NULL OR revoked_at = 0)",
                (now, user_id, keep_session_id)
            )
        else:
            self.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND (revoked_at IS NULL OR revoked_at = 0)",
                (now, user_id)
            )
        self.log_audit(user_id, "AUTH_REVOKE_OTHER_SESSIONS", details={"kept_session": keep_session_id})
        return True

    def get_identities(self, user_id: str) -> List[Dict[str, Any]]:
        rows = self.execute(
            "SELECT id, provider, provider_user_id, email, created_at FROM identities WHERE user_id = ? ORDER BY created_at ASC",
            (user_id,)
        )
        identities = []
        for r in (rows or []):
            identities.append({
                "id": self._row_val(r, "id", 0),
                "provider": self._row_val(r, "provider", 1),
                "provider_user_id": self._row_val(r, "provider_user_id", 2),
                "email": self._row_val(r, "email", 3),
                "created_at": self._row_val(r, "created_at", 4),
            })
        return identities

    def get_authorized_apps(self, user_id: str) -> List[Dict[str, Any]]:
        rows = self.execute("SELECT app_id, scopes, authorized_at FROM app_authorizations WHERE user_id = ?", (user_id,))
        auth_map = {}
        for r in (rows or []):
            aid = self._row_val(r, "app_id", 0)
            auth_map[aid] = {
                "scopes": self._row_val(r, "scopes", 1) or "sso:login",
                "authorized_at": self._row_val(r, "authorized_at", 2)
            }

        catalog = [
            {
                "id": "meikova-loop",
                "name": "Meikova Loop",
                "category": "Audio & DJ Streamer",
                "description": "Nền tảng hòa âm vô tận & stream âm thanh studio chất lượng cao",
                "color": "#FF8A50",
                "status": "connected" if "meikova-loop" in auth_map else "ready",
                "scopes": auth_map.get("meikova-loop", {}).get("scopes", "sso:profile,sso:sync"),
                "authorized_at": auth_map.get("meikova-loop", {}).get("authorized_at")
            },
            {
                "id": "meikova-harvest",
                "name": "Meikova Harvest",
                "category": "Media Extraction & Transcoding",
                "description": "Hạ tầng trích xuất đa phương tiện, tách stem Demucs và stream HLS",
                "color": "#00E5FF",
                "status": "connected" if "meikova-harvest" in auth_map else "ready",
                "scopes": auth_map.get("meikova-harvest", {}).get("scopes", "sso:profile,sso:download"),
                "authorized_at": auth_map.get("meikova-harvest", {}).get("authorized_at")
            },
            {
                "id": "meikova-relay",
                "name": "Meikova Relay",
                "category": "WebSocket Mesh & Remote Host",
                "description": "Điều khiển máy trạm từ xa, đồng bộ màn hình 60fps và DNS bypass",
                "color": "#22C55E",
                "status": "connected" if "meikova-relay" in auth_map else "ready",
                "scopes": auth_map.get("meikova-relay", {}).get("scopes", "sso:profile,sso:relay"),
                "authorized_at": auth_map.get("meikova-relay", {}).get("authorized_at")
            }
        ]
        return catalog

    def create_pat(self, user_id: str, name: str, scopes: str = "read,write", ttl_days: int = 90) -> Dict[str, Any]:
        clean_name = str(name or "Personal Access Token").strip()
        pat_id = f"pat_{uuid.uuid4().hex[:16]}"
        secret_rand = secrets.token_urlsafe(32)
        full_token = f"mkv_pat_{pat_id[4:]}_{secret_rand}"
        prefix = full_token[:16] + "..."
        token_hash = hashlib.sha256(full_token.encode("utf-8")).hexdigest()

        now = int(time.time())
        expires_at = now + (ttl_days * 86400)

        self.execute(
            "INSERT INTO personal_access_tokens (id, user_id, name, token_hash, token_prefix, scopes, created_at, expires_at, revoked_at, last_used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (pat_id, user_id, clean_name, token_hash, prefix, scopes, now, expires_at)
        )
        self.log_audit(user_id, "AUTH_TOKEN_CREATE", details={"pat_id": pat_id, "name": clean_name, "scopes": scopes})

        return {
            "id": pat_id,
            "name": clean_name,
            "token": full_token,
            "prefix": prefix,
            "scopes": scopes,
            "created_at": now,
            "expires_at": expires_at
        }

    def get_pats(self, user_id: str) -> List[Dict[str, Any]]:
        now = int(time.time())
        rows = self.execute(
            "SELECT id, name, token_prefix, scopes, created_at, expires_at, revoked_at, last_used_at "
            "FROM personal_access_tokens WHERE user_id = ? AND (revoked_at IS NULL OR revoked_at = 0) "
            "ORDER BY created_at DESC",
            (user_id,)
        )
        tokens = []
        for r in (rows or []):
            tokens.append({
                "id": self._row_val(r, "id", 0),
                "name": self._row_val(r, "name", 1),
                "prefix": self._row_val(r, "token_prefix", 2),
                "scopes": self._row_val(r, "scopes", 3),
                "created_at": self._row_val(r, "created_at", 4),
                "expires_at": self._row_val(r, "expires_at", 5),
                "is_expired": (self._row_val(r, "expires_at", 5) or 0) < now,
                "last_used_at": self._row_val(r, "last_used_at", 7),
            })
        return tokens

    def revoke_pat(self, user_id: str, pat_id: str) -> bool:
        now = int(time.time())
        self.execute(
            "UPDATE personal_access_tokens SET revoked_at = ? WHERE id = ? AND user_id = ?",
            (now, pat_id, user_id)
        )
        self.log_audit(user_id, "AUTH_TOKEN_REVOKE", details={"pat_id": pat_id})
        return True

    def log_audit(self, user_id: str, action: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        audit_id = f"aud_{uuid.uuid4().hex[:16]}"
        now = int(time.time())
        det_str = json.dumps(details or {}, ensure_ascii=False)
        ip = (ip_address or "127.0.0.1")[:45]
        ua = (user_agent or "")[:255]
        try:
            self.execute(
                "INSERT INTO audit_logs (id, user_id, action, ip_address, user_agent, details, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (audit_id, user_id, action, ip, ua, det_str, now)
            )
        except Exception as e:
            print(f"[Audit Log Error] {e}")

    def get_audit_logs(self, user_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self.execute(
            "SELECT id, action, ip_address, user_agent, details, created_at "
            "FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit)
        )
        logs = []
        for r in (rows or []):
            det = {}
            try:
                raw_det = self._row_val(r, "details", 4)
                if raw_det:
                    det = json.loads(raw_det)
            except Exception:
                pass
            logs.append({
                "id": self._row_val(r, "id", 0),
                "action": self._row_val(r, "action", 1),
                "ip_address": self._row_val(r, "ip_address", 2),
                "user_agent": self._row_val(r, "user_agent", 3),
                "details": det,
                "created_at": self._row_val(r, "created_at", 5),
            })
        return logs

    # === 2FA TOTP (RFC 6238) Engine ===

    def setup_totp(self, user_id: str) -> Dict[str, Any]:
        user = self.get_user_by_id(user_id)
        if not user:
            raise ValueError("Không tìm thấy tài khoản người dùng.")

        secret = generate_totp_secret()
        username = user.get("username", "user")
        issuer = "Meikova Auth"
        encoded_issuer = urllib.parse.quote(issuer)
        encoded_label = urllib.parse.quote(f"{issuer}:{username}")
        otpauth_url = f"otpauth://totp/{encoded_label}?secret={secret}&issuer={encoded_issuer}&algorithm=SHA1&digits=6&period=30"

        return {
            "secret": secret,
            "otpauth_url": otpauth_url,
            "qr_data": otpauth_url
        }

    def enable_totp(self, user_id: str, secret: str, code: str) -> Dict[str, Any]:
        clean_code = str(code or "").strip()
        clean_secret = str(secret or "").strip().upper()
        if not clean_code or not clean_secret:
            raise ValueError("Mã xác thực và secret không được để trống.")

        if not verify_totp_code(clean_secret, clean_code):
            raise ValueError("Mã xác thực 6 số không chính xác hoặc đã hết hạn.")

        backup_codes = [secrets.token_hex(4).upper() for _ in range(8)]

        self.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_backup_codes = ? WHERE id = ?",
            (clean_secret, json.dumps(backup_codes), user_id)
        )

        self.log_audit(user_id, "AUTH_TOTP_ENABLED", details={"backup_codes_count": len(backup_codes)})

        return {
            "success": True,
            "backup_codes": backup_codes
        }

    def verify_totp_login(
        self,
        user_id: str,
        code: str,
        device_name: Optional[str] = None,
        device_type: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        totp_key = f"totp_user:{user_id}"
        is_locked, _, retry_sec = strike_tracker.check_lock(totp_key)
        if is_locked:
            raise ValueError(f"AUTH_RATE_LIMITED:{retry_sec}")

        clean_code = str(code or "").strip().upper()
        if not clean_code:
            raise ValueError("Mã xác thực không được để trống.")

        row = self.fetchone(
            "SELECT id, username, email, display_name, role, totp_secret, totp_backup_codes, totp_enabled FROM users WHERE id = ?",
            (user_id,)
        )
        if not row:
            raise ValueError("Không tìm thấy tài khoản người dùng.")

        user_id = self._row_val(row, "id", 0)
        username = self._row_val(row, "username", 1)
        email = self._row_val(row, "email", 2)
        display_name = self._row_val(row, "display_name", 3)
        role = self._row_val(row, "role", 4) or "user"
        totp_secret = self._row_val(row, "totp_secret", 5)
        backup_codes_raw = self._row_val(row, "totp_backup_codes", 6)
        totp_enabled = bool(self._row_val(row, "totp_enabled", 7, 0))

        if not totp_enabled or not totp_secret:
            raise ValueError("Tài khoản chưa kích hoạt bảo mật 2FA.")

        is_valid = False
        used_backup_code = False

        if clean_code.isdigit() and len(clean_code) == 6:
            is_valid = verify_totp_code(totp_secret, clean_code)

        if not is_valid and backup_codes_raw:
            try:
                backup_codes = json.loads(backup_codes_raw)
                if isinstance(backup_codes, list) and clean_code in backup_codes:
                    is_valid = True
                    used_backup_code = True
                    backup_codes.remove(clean_code)
                    self.execute(
                        "UPDATE users SET totp_backup_codes = ? WHERE id = ?",
                        (json.dumps(backup_codes), user_id)
                    )
            except Exception:
                pass

        if not is_valid:
            is_locked, strikes, retry_sec = strike_tracker.record_failure(totp_key)
            if is_locked:
                self.log_audit(user_id, "SECURITY_ALERT_TOTP_LOCKED", ip_address=ip_address, user_agent=user_agent)
                raise ValueError(f"AUTH_RATE_LIMITED:{retry_sec}")
            self.log_audit(user_id, "AUTH_TOTP_FAILED", ip_address=ip_address, user_agent=user_agent)
            raise ValueError("Mã xác thực TOTP hoặc mã dự phòng không chính xác.")

        # Clear strikes on valid TOTP
        strike_tracker.record_success(totp_key)

        session_id = self.create_session(
            user_id=user_id,
            device_name=device_name or "Trình duyệt Web",
            device_type=device_type or "web",
            user_agent=user_agent,
            ip_address=ip_address
        )

        sso_token = issue_universal_token(
            user_id=user_id,
            username=username,
            email=email,
            display_name=display_name or username,
            role=role
        )

        audit_details = {"session_id": session_id, "method": "backup_code" if used_backup_code else "totp"}
        self.log_audit(user_id, "AUTH_LOGIN_TOTP", ip_address=ip_address, user_agent=user_agent, details=audit_details)

        return {
            "status": "ok",
            "token": sso_token,
            "session_id": session_id,
            "used_backup_code": used_backup_code,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "display_name": display_name or username,
                "role": role
            }
        }

    def disable_totp(self, user_id: str, password: Optional[str] = None, code: Optional[str] = None) -> bool:
        row = self.fetchone(
            "SELECT password_hash, salt, totp_secret, totp_enabled FROM users WHERE id = ?",
            (user_id,)
        )
        if not row:
            raise ValueError("Không tìm thấy người dùng.")

        expected_hash = self._row_val(row, "password_hash", 0)
        salt = self._row_val(row, "salt", 1)
        totp_secret = self._row_val(row, "totp_secret", 2)

        verified = False
        if password and expected_hash and salt:
            verified = self.verify_password_hash(password, salt, expected_hash)
        if not verified and code and totp_secret:
            verified = verify_totp_code(totp_secret, str(code).strip())

        if not verified:
            raise ValueError("Mật khẩu hoặc mã xác thực không đúng để tắt 2FA.")

        self.execute(
            "UPDATE users SET totp_enabled = 0, totp_secret = NULL, totp_backup_codes = NULL WHERE id = ?",
            (user_id,)
        )

        self.log_audit(user_id, "AUTH_TOTP_DISABLED")
        return True

    # === Security PIN Engine (6-Digit App Lock & Step-Up Auth) ===

    def setup_pin(self, user_id: str, pin: str, password: str) -> bool:
        clean_pin = str(pin or "").strip()
        if len(clean_pin) != 6 or not clean_pin.isdigit():
            raise ValueError("Mã PIN phải bao gồm đúng 6 chữ số.")

        row = self.fetchone("SELECT password_hash, salt FROM users WHERE id = ?", (user_id,))
        if not row:
            raise ValueError("Không tìm thấy tài khoản người dùng.")

        expected_hash = self._row_val(row, "password_hash", 0)
        salt = self._row_val(row, "salt", 1)

        if expected_hash and salt:
            if not self.verify_password_hash(password, salt, expected_hash):
                raise ValueError("Mật khẩu tài khoản không chính xác.")

        pin_salt = secrets.token_hex(16)
        pin_hash = self.hash_password(clean_pin, pin_salt)

        self.execute(
            "UPDATE users SET pin_hash = ?, pin_salt = ?, pin_enabled = 1 WHERE id = ?",
            (pin_hash, pin_salt, user_id)
        )

        self.log_audit(user_id, "AUTH_PIN_SETUP")
        return True

    def verify_pin(self, user_id: str, pin: str) -> bool:
        pin_key = f"pin_user:{user_id}"
        is_locked, _, retry_sec = strike_tracker.check_lock(pin_key)
        if is_locked:
            raise ValueError(f"AUTH_RATE_LIMITED:{retry_sec}")

        clean_pin = str(pin or "").strip()
        if len(clean_pin) != 6 or not clean_pin.isdigit():
            raise ValueError("Mã PIN phải gồm đúng 6 chữ số.")

        row = self.fetchone("SELECT pin_hash, pin_salt, pin_enabled FROM users WHERE id = ?", (user_id,))
        if not row:
            raise ValueError("Không tìm thấy tài khoản người dùng.")

        pin_hash = self._row_val(row, "pin_hash", 0)
        pin_salt = self._row_val(row, "pin_salt", 1)
        pin_enabled = bool(self._row_val(row, "pin_enabled", 2, 0))

        if not pin_enabled or not pin_hash or not pin_salt:
            raise ValueError("Chưa thiết lập mã PIN cho tài khoản.")

        if not self.verify_password_hash(clean_pin, pin_salt, pin_hash):
            is_locked, strikes, retry_sec = strike_tracker.record_failure(pin_key)
            if is_locked:
                self.log_audit(user_id, "SECURITY_ALERT_PIN_LOCKED")
                raise ValueError(f"AUTH_RATE_LIMITED:{retry_sec}")
            self.log_audit(user_id, "AUTH_PIN_VERIFY_FAILED")
            raise ValueError("Mã PIN không chính xác.")

        # Reset strikes on valid PIN verification
        strike_tracker.record_success(pin_key)
        self.log_audit(user_id, "AUTH_PIN_VERIFIED")
        return True

    def change_pin(self, user_id: str, new_pin: str, old_pin: Optional[str] = None, password: Optional[str] = None) -> bool:
        clean_new = str(new_pin or "").strip()
        if len(clean_new) != 6 or not clean_new.isdigit():
            raise ValueError("Mã PIN mới phải bao gồm đúng 6 chữ số.")

        row = self.fetchone("SELECT password_hash, salt, pin_hash, pin_salt, pin_enabled FROM users WHERE id = ?", (user_id,))
        if not row:
            raise ValueError("Không tìm thấy tài khoản người dùng.")

        pw_hash = self._row_val(row, "password_hash", 0)
        pw_salt = self._row_val(row, "salt", 1)
        curr_pin_hash = self._row_val(row, "pin_hash", 2)
        curr_pin_salt = self._row_val(row, "pin_salt", 3)

        verified = False
        if old_pin and curr_pin_hash and curr_pin_salt:
            verified = self.verify_password_hash(str(old_pin).strip(), curr_pin_salt, curr_pin_hash)
        if not verified and password and pw_hash and pw_salt:
            verified = self.verify_password_hash(password, pw_salt, pw_hash)

        if not verified:
            raise ValueError("Mã PIN hiện tại hoặc mật khẩu không chính xác.")

        pin_salt = secrets.token_hex(16)
        pin_hash = self.hash_password(clean_new, pin_salt)

        self.execute(
            "UPDATE users SET pin_hash = ?, pin_salt = ?, pin_enabled = 1 WHERE id = ?",
            (pin_hash, pin_salt, user_id)
        )

        self.log_audit(user_id, "AUTH_PIN_CHANGED")
        return True

    def disable_pin(self, user_id: str, password: str) -> bool:
        row = self.fetchone("SELECT password_hash, salt FROM users WHERE id = ?", (user_id,))
        if not row:
            raise ValueError("Không tìm thấy tài khoản người dùng.")

        pw_hash = self._row_val(row, "password_hash", 0)
        pw_salt = self._row_val(row, "salt", 1)

        if pw_hash and pw_salt:
            if not self.verify_password_hash(password, pw_salt, pw_hash):
                raise ValueError("Mật khẩu tài khoản không chính xác.")

        self.execute(
            "UPDATE users SET pin_hash = NULL, pin_salt = NULL, pin_enabled = 0 WHERE id = ?",
            (user_id,)
        )

        self.log_audit(user_id, "AUTH_PIN_DISABLED")
        return True

    def get_security_status(self, user_id: str) -> Dict[str, Any]:
        row = self.fetchone("SELECT totp_enabled, pin_enabled FROM users WHERE id = ?", (user_id,))
        if not row:
            return {"totp_enabled": False, "pin_enabled": False}
        return {
            "totp_enabled": bool(self._row_val(row, "totp_enabled", 0, 0)),
            "pin_enabled": bool(self._row_val(row, "pin_enabled", 1, 0))
        }

    @staticmethod
    def get_host_info(request_host: Optional[str] = None, port: int = 8990) -> Dict[str, Any]:
        lan_ip = "127.0.0.1"
        tailscale_ip = None
        try:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                lan_ip = s.getsockname()[0]
        except Exception:
            pass

        try:
            import socket
            hostname = socket.gethostname()
            for ip in socket.gethostbyname_ex(hostname)[2]:
                if ip.startswith("100."):
                    tailscale_ip = ip
                    break
        except Exception:
            pass

        public_url = os.environ.get("RENDER_EXTERNAL_URL") or os.environ.get("PUBLIC_URL")
        if not public_url and request_host:
            scheme = "https" if ("443" in request_host or "onrender.com" in request_host or "hf.space" in request_host) else "http"
            public_url = f"{scheme}://{request_host}"

        active_url = public_url or (f"http://{tailscale_ip}:{port}" if tailscale_ip else f"http://{lan_ip}:{port}")
        is_local = "127.0.0.1" in active_url or "localhost" in active_url

        return {
            "status": "online",
            "lan_ip": lan_ip,
            "lan_url": f"http://{lan_ip}:{port}",
            "tailscale_ip": tailscale_ip,
            "tailscale_url": f"http://{tailscale_ip}:{port}" if tailscale_ip else None,
            "active_url": active_url,
            "is_local": is_local,
            "port": port
        }

    @staticmethod
    def resolve_app_asset(platform: str) -> Dict[str, Any]:
        repo = "https://github.com/meikova/meikova-auth"
        base_release = f"{repo}/releases/latest/download"
        platforms = {
            "windows": {
                "unversioned_filename": "MeikovaAuth-Setup.exe",
                "download_url": f"{base_release}/MeikovaAuth-Setup.exe",
                "type": "Installer (.exe)",
                "os": "Windows 10 / 11 (64-bit)"
            },
            "macos": {
                "unversioned_filename": "MeikovaAuth.dmg",
                "download_url": f"{base_release}/MeikovaAuth.dmg",
                "type": "Disk Image (.dmg)",
                "os": "macOS 12+ (Apple Silicon / Intel)"
            },
            "linux": {
                "unversioned_filename": "MeikovaAuth.AppImage",
                "download_url": f"{base_release}/MeikovaAuth.AppImage",
                "type": "AppImage (.AppImage)",
                "os": "Ubuntu / Debian / Fedora / Arch"
            },
            "android": {
                "unversioned_filename": "MeikovaAuth.apk",
                "download_url": f"{base_release}/MeikovaAuth.apk",
                "type": "PWA & APK Standalone",
                "os": "Android 8.0+"
            }
        }
        target = platform.lower().strip()
        if target not in platforms:
            target = "windows"
        return {
            "success": True,
            "platform": target,
            "asset": platforms[target],
            "fallback_portal": "/login"
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

    def google_auth(
        self,
        credential: str,
        device_name: Optional[str] = None,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
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
                session_id = self.create_session(user_id, device_name, "web", user_agent, ip_address)
                self.log_audit(user_id, "AUTH_GOOGLE_LOGIN", ip_address=ip_address, user_agent=user_agent)
                return {"status": "ok", "token": token, "session_id": session_id, "user": user_data}

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

            session_id = self.create_session(user_id, device_name, "web", user_agent, ip_address)
            token = issue_universal_token(user_id=user_id, username=username, email=email, display_name=display_name, role=role)
            self.log_audit(user_id, "AUTH_GOOGLE_LINK", ip_address=ip_address, user_agent=user_agent)
            return {
                "status": "ok",
                "token": token,
                "session_id": session_id,
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

        session_id = self.create_session(user_id, device_name, "web", user_agent, ip_address)
        token = issue_universal_token(user_id=user_id, username=candidate_username, email=email, display_name=disp_name, role="user")
        self.log_audit(user_id, "AUTH_GOOGLE_REGISTER", ip_address=ip_address, user_agent=user_agent)
        return {
            "status": "ok",
            "token": token,
            "session_id": session_id,
            "user": {
                "id": user_id,
                "username": candidate_username,
                "email": email,
                "display_name": disp_name,
                "avatar_url": avatar_url,
                "role": "user"
            }
        }

    def get_crl(self) -> Dict[str, Any]:
        """Tra cứu danh sách các phiên hoặc người dùng đã bị thu hồi (Certificate/Token Revocation List)."""
        rows = self.execute("SELECT id, user_id, revoked_at FROM sessions WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC LIMIT 100")
        revoked_sessions = []
        for r in rows:
            revoked_sessions.append({
                "session_id": self._row_val(r, "id", 0),
                "user_id": self._row_val(r, "user_id", 1),
                "revoked_at": self._row_val(r, "revoked_at", 2),
            })
        return {
            "revoked": revoked_sessions,
            "count": len(revoked_sessions),
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
