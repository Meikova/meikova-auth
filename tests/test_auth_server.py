# -*- coding: utf-8 -*-
"""
Meikova Auth Gateway & Credential Manager Comprehensive Test Suite
Validates:
- Centralized Registration & Authentication
- Ed25519 Token Signing & Zero-Roundtrip Verification
- Google OAuth 1-Click Identity Linking
- Credential Management: Profile Update, Password Change (PBKDF2-SHA256 600k)
- Active Sessions & Remote Revocation
- Personal Access Tokens (PAT) & Ecosystem Authorizations
- Security Audit Trail
- Dynamic Host Discovery & Zero-Hardcoded-QR (Rule 18)
- Dynamic App Download Resolution (Rule 15)
- Tampered & Expired Token Gating
"""

import os
import sys
import time
import json
import socket
import urllib.request
import urllib.error
import threading
from pathlib import Path

AUTH_ROOT = Path(__file__).resolve().parent.parent

# Guarantee Ed25519 test keys
if not os.environ.get("AUTH_PRIVATE_KEY_PEM"):
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        _ci_key = ed25519.Ed25519PrivateKey.generate()
        os.environ["AUTH_PRIVATE_KEY_PEM"] = _ci_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")
        os.environ["AUTH_PUBLIC_KEY_PEM"] = _ci_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
    except Exception as _e:
        print(f"[CI Key Setup Warning] {_e}")

if str(AUTH_ROOT) not in sys.path:
    sys.path.insert(0, str(AUTH_ROOT))

from core.universal_sso import issue_universal_token, verify_universal_token, _b64url_encode
from core.auth_gateway import generate_totp_code

PASS_COUNT = 0
FAIL_COUNT = 0


def log_step(name: str, passed: bool, detail: str = ""):
    global PASS_COUNT, FAIL_COUNT
    if passed:
        PASS_COUNT += 1
        print(f"[PASS] {name} {detail}".strip())
    else:
        FAIL_COUNT += 1
        print(f"[FAIL] {name} {detail}".strip())


def find_free_port(start_port: int = 8990) -> int:
    port = start_port
    while port < 9999:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
        port += 1
    return start_port


def http_request(url: str, method: str = "GET", data: dict = None, headers: dict = None) -> tuple[int, dict]:
    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            code = resp.status
            content = resp.read().decode("utf-8")
            try:
                res_json = json.loads(content)
            except Exception:
                res_json = {"raw": content}
            return code, res_json
    except urllib.error.HTTPError as e:
        code = e.code
        err_content = e.read().decode("utf-8")
        try:
            err_json = json.loads(err_content)
        except Exception:
            err_json = {"error": err_content}
        return code, err_json
    except Exception as ex:
        return 0, {"error": str(ex)}


def run_tests():
    global PASS_COUNT, FAIL_COUNT
    port = find_free_port(8995)
    base_url = f"http://127.0.0.1:{port}"
    print(f"\n--- Starting Meikova Auth Gateway Test Server on {base_url} ---")

    # Start Uvicorn in background thread
    import uvicorn
    from server import app

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server ready
    ready = False
    for _ in range(50):
        time.sleep(0.1)
        code, body = http_request(f"{base_url}/health")
        if code == 200:
            ready = True
            break

    log_step("Server Startup", ready, f"Running on {base_url}")
    if not ready:
        print("[FATAL] Server failed to start")
        sys.exit(1)

    # 1. Healthcheck
    code, body = http_request(f"{base_url}/health")
    log_step("GET /health", code == 200 and body.get("status") == "healthy", f"Backend: {body.get('database', {}).get('backend')}, Keys Loaded: {body.get('crypto', {}).get('public_key_loaded')}")

    # 1.1 Web SSO Portal & Dashboard Pages
    req_login = urllib.request.Request(f"{base_url}/login")
    with urllib.request.urlopen(req_login) as resp:
        login_html = resp.read().decode("utf-8")
        log_step("GET /login (SSO Portal UI)", resp.status == 200 and "Meikova Auth" in login_html)

    req_reg = urllib.request.Request(f"{base_url}/register")
    with urllib.request.urlopen(req_reg) as resp:
        reg_html = resp.read().decode("utf-8")
        log_step("GET /register (SSO Portal UI)", resp.status == 200 and "Tạo tài khoản" in reg_html)

    req_dash = urllib.request.Request(f"{base_url}/dashboard")
    with urllib.request.urlopen(req_dash) as resp:
        dash_html = resp.read().decode("utf-8")
        log_step("GET /dashboard (Credential Manager SPA)", resp.status == 200 and "Meikova Auth" in dash_html and "Hồ Sơ Danh Tính" in dash_html)

    # 2. Key Export & JWKS
    code, body = http_request(f"{base_url}/api/auth/keys")
    log_step("GET /api/auth/keys", code == 200 and "public_key_pem" in body, f"Alg: {body.get('algorithm')}, JWKS keys: {len(body.get('jwks', {}).get('keys', []))}")

    code, body = http_request(f"{base_url}/.well-known/jwks.json")
    log_step("GET /.well-known/jwks.json", code == 200 and "keys" in body, f"Keys: {len(body.get('keys', []))}")

    # 2.1 Auth Config
    code, body = http_request(f"{base_url}/api/auth/config")
    log_step("GET /api/auth/config", code == 200 and "515668723869" in body.get("google_client_id", ""), f"Google Client ID: {body.get('google_client_id')}")

    # 3. Registration
    ts = int(time.time())
    test_username = f"meikova_test_{ts}"
    test_email = f"meikova_{ts}@meikova.io"
    test_password = "MeikovaSecretPassword123"

    reg_payload = {
        "username": test_username,
        "password": test_password,
        "email": test_email,
        "display_name": "Meikova Test Master"
    }
    code, body = http_request(f"{base_url}/api/auth/register", method="POST", data=reg_payload)
    user_id = body.get("user", {}).get("id")
    token = body.get("token")
    session_id = body.get("session_id")
    log_step("POST /api/auth/register (New User)", code == 201 and bool(token) and bool(session_id), f"User ID: {user_id}, Session: {session_id}")

    # 4. Duplicate Registration Rejection
    code, dup_body = http_request(f"{base_url}/api/auth/register", method="POST", data=reg_payload)
    log_step("POST /api/auth/register (Duplicate Rejection)", code == 409, f"Status code: {code}")

    # 5. Login by Username
    login_payload = {"username": test_username, "password": test_password}
    code, login_body = http_request(f"{base_url}/api/auth/login", method="POST", data=login_payload)
    login_token = login_body.get("token")
    log_step("POST /api/auth/login (by Username)", code == 200 and bool(login_token), f"Token received: {bool(login_token)}")

    # 6. Login by Email
    login_email_payload = {"identifier": test_email, "password": test_password}
    code, login_email_body = http_request(f"{base_url}/api/auth/login", method="POST", data=login_email_payload)
    log_step("POST /api/auth/login (by Email)", code == 200 and bool(login_email_body.get("token")), f"Email: {test_email}")

    # 7. Login with Wrong Password
    code, wrong_body = http_request(f"{base_url}/api/auth/login", method="POST", data={"username": test_username, "password": "WrongPassword"})
    log_step("POST /api/auth/login (Wrong Password)", code == 401, f"Rejected with {code}")

    # 8. Offline Token Verification
    offline_verified = verify_universal_token(token)
    log_step("Offline Ed25519 Token Verification", offline_verified is not None and offline_verified["sub"] == user_id, f"Matched sub: {offline_verified.get('sub') if offline_verified else None}")

    # 9. Server Token Verification Endpoint (GET)
    code, verify_body = http_request(f"{base_url}/api/auth/verify?token={token}")
    log_step("GET /api/auth/verify", code == 200 and verify_body.get("valid") is True, f"Valid: {verify_body.get('valid')}")

    # 10. Server Token Verification Endpoint (POST)
    code, verify_post_body = http_request(f"{base_url}/api/auth/verify", method="POST", data={"token": token})
    log_step("POST /api/auth/verify", code == 200 and verify_post_body.get("valid") is True, f"Valid: {verify_post_body.get('valid')}")

    # 11. Profile Endpoint (/api/auth/me) with Bearer token
    auth_headers = {"Authorization": f"Bearer {token}"}
    code, me_body = http_request(f"{base_url}/api/auth/me", headers=auth_headers)
    me_user = me_body.get("user", {})
    log_step("GET /api/auth/me (Bearer Token)", code == 200 and me_user.get("id") == user_id, f"Username: {me_user.get('username')}, Role: {me_user.get('role')}")

    # 12. Credential Management: Profile Update
    updated_name = "Nguyen Van Meikova"
    updated_email = f"updated_{ts}@meikova.io"
    code, prof_body = http_request(
        f"{base_url}/api/auth/profile",
        method="PATCH",
        data={"display_name": updated_name, "email": updated_email},
        headers=auth_headers
    )
    log_step("PATCH /api/auth/profile", code == 200 and prof_body.get("code") == "AUTH_PROFILE_UPDATED", f"New Name: {prof_body.get('user', {}).get('display_name')}")

    # 13. Credential Management: Password Change
    new_password = "MyNewSecurePassword456"
    code, pwd_body = http_request(
        f"{base_url}/api/auth/password",
        method="POST",
        data={"old_password": test_password, "new_password": new_password},
        headers=auth_headers
    )
    log_step("POST /api/auth/password", code == 200 and pwd_body.get("code") == "AUTH_PASSWORD_CHANGED")

    # 14. Verify Login with New Password
    code, new_login_body = http_request(f"{base_url}/api/auth/login", method="POST", data={"username": test_username, "password": new_password})
    log_step("POST /api/auth/login (with New Password)", code == 200 and bool(new_login_body.get("token")), f"Token received: {bool(new_login_body.get('token'))}")

    # 15. Active Sessions Management
    code, sess_body = http_request(f"{base_url}/api/auth/sessions", headers=auth_headers)
    sessions = sess_body.get("sessions", [])
    log_step("GET /api/auth/sessions", code == 200 and len(sessions) >= 1, f"Active sessions count: {len(sessions)}")

    if sessions:
        target_sess_id = sessions[0]["id"]
        code, rev_body = http_request(f"{base_url}/api/auth/sessions/{target_sess_id}", method="DELETE", headers=auth_headers)
        log_step("DELETE /api/auth/sessions/{id}", code == 200 and rev_body.get("code") == "AUTH_SESSION_REVOKED")

    code, rev_all_body = http_request(f"{base_url}/api/auth/sessions/revoke-others", method="POST", headers=auth_headers)
    log_step("POST /api/auth/sessions/revoke-others", code == 200 and rev_all_body.get("code") == "AUTH_ALL_SESSIONS_REVOKED")

    # 16. Personal Access Tokens (PAT)
    code, pat_create_body = http_request(
        f"{base_url}/api/auth/tokens",
        method="POST",
        data={"name": "CLI Automation Token", "scopes": "read,write", "ttl_days": 60},
        headers=auth_headers
    )
    raw_pat = pat_create_body.get("token", {}).get("token", "")
    pat_id = pat_create_body.get("token", {}).get("id")
    log_step("POST /api/auth/tokens", code == 201 and raw_pat.startswith("mkv_pat_"), f"PAT Prefix: {raw_pat[:16]}")

    code, pats_body = http_request(f"{base_url}/api/auth/tokens", headers=auth_headers)
    log_step("GET /api/auth/tokens", code == 200 and len(pats_body.get("tokens", [])) >= 1)

    if pat_id:
        code, pat_rev_body = http_request(f"{base_url}/api/auth/tokens/{pat_id}", method="DELETE", headers=auth_headers)
        log_step("DELETE /api/auth/tokens/{id}", code == 200 and pat_rev_body.get("code") == "AUTH_TOKEN_REVOKED")

    # 17. Ecosystem Authorizations & Linked Identities
    code, apps_body = http_request(f"{base_url}/api/auth/apps", headers=auth_headers)
    apps = apps_body.get("apps", [])
    log_step("GET /api/auth/apps", code == 200 and len(apps) >= 3, f"Apps found: {[a['id'] for a in apps]}")

    code, idents_body = http_request(f"{base_url}/api/auth/identities", headers=auth_headers)
    log_step("GET /api/auth/identities", code == 200 and isinstance(idents_body.get("identities"), list))

    # 18. Security Audit Logs
    code, audit_body = http_request(f"{base_url}/api/auth/audit?limit=10", headers=auth_headers)
    logs = audit_body.get("logs", [])
    log_step("GET /api/auth/audit", code == 200 and len(logs) >= 1, f"Audit entries recorded: {len(logs)}")

    # 19. Rule 18: Dynamic Host Discovery
    for ep in ["/api/host-info", "/api/network/host-info"]:
        code, host_data = http_request(f"{base_url}{ep}")
        log_step(f"GET {ep} (Rule 18 Host Discovery)", code == 200 and "lan_ip" in host_data and "active_url" in host_data, f"LAN: {host_data.get('lan_ip')}, Active: {host_data.get('active_url')}")

    # 20. Rule 18: Dynamic QR Code Endpoint
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(f"{base_url}/api/qr?data=https%3A%2F%2Fmeikova.io")
        qr_status = resp.status
        loc = resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        qr_status = e.code
        loc = e.headers.get("Location", "")
    except Exception:
        qr_status = 0
        loc = ""
    log_step("GET /api/qr (Rule 18 QR Endpoint)", qr_status == 200 or (qr_status == 307 and "qrserver.com" in loc), f"Status: {qr_status}")

    # 21. Rule 15: Dynamic App Download Resolvers
    code, win_asset = http_request(f"{base_url}/api/download/app/windows")
    log_step("GET /api/download/app/windows (Rule 15)", code == 200 and win_asset.get("asset", {}).get("unversioned_filename") == "MeikovaAuth-Setup.exe")

    code, mac_asset = http_request(f"{base_url}/api/download/app/macos")
    log_step("GET /api/download/app/macos (Rule 15)", code == 200 and mac_asset.get("asset", {}).get("unversioned_filename") == "MeikovaAuth.dmg")

    # 22. Google OAuth 1-Click Login / Auto-Provisioning
    dummy_google_sub = f"google_sub_{ts}"
    dummy_google_email = f"google_{ts}@gmail.com"
    dummy_header = _b64url_encode(json.dumps({"alg": "RS256"}).encode("utf-8"))
    dummy_payload = _b64url_encode(json.dumps({
        "sub": dummy_google_sub,
        "email": dummy_google_email,
        "name": f"Google User {ts}",
        "picture": "https://lh3.googleusercontent.com/dummy.jpg"
    }).encode("utf-8"))
    fake_google_id_token = f"{dummy_header}.{dummy_payload}.signaturesig"

    code, g_body = http_request(f"{base_url}/api/auth/google", method="POST", data={"credential": fake_google_id_token})
    g_token = g_body.get("token")
    g_user_id = g_body.get("user", {}).get("id")
    log_step("POST /api/auth/google (1-Click Auto Provision)", code == 200 and bool(g_token), f"User: {g_body.get('user', {}).get('username')}, ID: {g_user_id}")

    # 23. Google OAuth Deduplication / Link
    code, g_body2 = http_request(f"{base_url}/api/auth/google", method="POST", data={"credential": fake_google_id_token})
    log_step("POST /api/auth/google (Identity Link Deduplication)", code == 200 and g_body2.get("user", {}).get("id") == g_user_id, f"Deduplicated to User ID: {g_body2.get('user', {}).get('id')}")

    # 24. Tampered Token Rejection
    tampered_token = (token or "dummytoken12345678")[:-4] + "AAAA"
    code, _ = http_request(f"{base_url}/api/auth/verify?token={tampered_token}")
    log_step("Tampered Token Rejection (Verify API)", code == 401, f"Code: {code}")

    code, _ = http_request(f"{base_url}/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    log_step("Tampered Token Rejection (Me API)", code == 401, f"Code: {code}")

    # 25. Expired Token Rejection
    expired_token = issue_universal_token(user_id="usr_expired", username="expired_user", expires_in_sec=-3600)
    code, _ = http_request(f"{base_url}/api/auth/verify?token={expired_token}")
    log_step("Expired Token Rejection (Verify API)", code == 401, f"Code: {code}")

    # 26. Missing Token Rejection
    code, _ = http_request(f"{base_url}/api/auth/me")
    log_step("Missing Token Rejection", code == 401, f"Code: {code}")

    # 27. Security Status (Initial state)
    code, sec_status = http_request(f"{base_url}/api/auth/security/status", headers=auth_headers)
    log_step("GET /api/auth/security/status", code == 200 and sec_status.get("totp_enabled") is False and sec_status.get("pin_enabled") is False)

    # 28. TOTP 2FA Setup
    code, totp_setup = http_request(f"{base_url}/api/auth/totp/setup", method="POST", headers=auth_headers)
    totp_secret = totp_setup.get("secret")
    log_step("POST /api/auth/totp/setup", code == 200 and bool(totp_secret), f"Secret: {totp_secret[:8]}...")

    # 29. TOTP 2FA Enable
    valid_code = generate_totp_code(totp_secret)
    code, totp_enable = http_request(
        f"{base_url}/api/auth/totp/enable",
        method="POST",
        headers=auth_headers,
        data={"secret": totp_secret, "code": valid_code}
    )
    backup_codes = totp_enable.get("backup_codes", [])
    log_step("POST /api/auth/totp/enable", code == 200 and len(backup_codes) == 8, f"Status: {code}, Backup codes: {len(backup_codes)}, Body: {totp_enable}")

    # 30. Login with TOTP Enabled -> Requires 2FA Step
    code, totp_login_res = http_request(
        f"{base_url}/api/auth/login",
        method="POST",
        data={"username": test_username, "password": new_password}
    )
    temp_token = totp_login_res.get("temp_token")
    log_step("POST /api/auth/login (with 2FA Enabled)", code == 200 and totp_login_res.get("require_totp") is True and bool(temp_token), "Gated by 2FA")

    # 31. Verify TOTP with Invalid Code -> Rejected
    code, _ = http_request(
        f"{base_url}/api/auth/totp/verify",
        method="POST",
        data={"temp_token": temp_token, "code": "000000"}
    )
    log_step("POST /api/auth/totp/verify (Invalid Code)", code == 401, f"Rejected with {code}")

    # 32. Verify TOTP with Valid Code -> Success and Token Issued
    valid_login_code = generate_totp_code(totp_secret)
    code, verified_login = http_request(
        f"{base_url}/api/auth/totp/verify",
        method="POST",
        data={"temp_token": temp_token, "code": valid_login_code}
    )
    log_step("POST /api/auth/totp/verify (Valid Code)", code == 200 and bool(verified_login.get("token")), "Universal Token Issued")

    # 33. Disable TOTP
    code, dis_res = http_request(
        f"{base_url}/api/auth/totp/disable",
        method="POST",
        headers=auth_headers,
        data={"password": new_password}
    )
    log_step("POST /api/auth/totp/disable", code == 200, f"Status: {code}, Body: {dis_res}")

    # 34. Setup 6-Digit Security PIN
    test_pin = "852963"
    code, pin_setup_res = http_request(
        f"{base_url}/api/auth/pin/setup",
        method="POST",
        headers=auth_headers,
        data={"pin": test_pin, "password": new_password}
    )
    log_step("POST /api/auth/pin/setup", code == 200 and pin_setup_res.get("success") is True, f"PIN: {test_pin}")

    # 35. Verify Security PIN (Wrong vs Correct)
    code, _ = http_request(
        f"{base_url}/api/auth/pin/verify",
        method="POST",
        headers=auth_headers,
        data={"pin": "111111"}
    )
    log_step("POST /api/auth/pin/verify (Wrong PIN)", code == 401, f"Rejected with {code}")

    code, pin_verify_res = http_request(
        f"{base_url}/api/auth/pin/verify",
        method="POST",
        headers=auth_headers,
        data={"pin": test_pin}
    )
    log_step("POST /api/auth/pin/verify (Correct PIN)", code == 200 and pin_verify_res.get("verified") is True, "PIN Verified")

    # 36. Change Security PIN
    new_pin = "369258"
    code, pin_change_res = http_request(
        f"{base_url}/api/auth/pin/change",
        method="POST",
        headers=auth_headers,
        data={"old_pin": test_pin, "new_pin": new_pin}
    )
    log_step("POST /api/auth/pin/change", code == 200 and pin_change_res.get("success") is True, f"New PIN: {new_pin}")

    # 37. Disable Security PIN
    code, pin_disable_res = http_request(
        f"{base_url}/api/auth/pin/disable",
        method="POST",
        headers=auth_headers,
        data={"password": new_password}
    )
    log_step("POST /api/auth/pin/disable", code == 200 and pin_disable_res.get("success") is True, "PIN Disabled")

    # Shutdown server
    server.should_exit = True
    server_thread.join(timeout=2.0)

    print(f"\n--- Summary ---")
    print(f"Total Passed: {PASS_COUNT}")
    print(f"Total Failed: {FAIL_COUNT}")
    if FAIL_COUNT > 0:
        print("[FAIL] Some tests failed.")
        sys.exit(1)
    print("[SUCCESS] All Meikova Auth Gateway tests passed successfully with Exit Code 0.")
    sys.exit(0)


if __name__ == "__main__":
    run_tests()
