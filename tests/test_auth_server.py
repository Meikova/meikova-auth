# -*- coding: utf-8 -*-
"""
Meikova Auth Gateway & Universal SSO Automated Verification Suite
Tests the running HTTP REST service against Turso Cloud SQLite (`meikova-auth`)
and Ed25519 cryptographic token issuing/verification.
Zero-emoji compliant.
"""

import os
import sys
import time
import json
import base64
import socket
import threading
import urllib.request
import urllib.error
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
AUTH_ROOT = TEST_DIR.parent
KEYS_DIR = AUTH_ROOT / "keys"

# Ensure test Ed25519 keys exist in CI environment (GitHub Actions)
if not os.environ.get("AUTH_PRIVATE_KEY_PEM") and not (KEYS_DIR / "ed25519_private.pem").exists():
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

    # 1.1 Web SSO Portal Pages
    req_login = urllib.request.Request(f"{base_url}/login")
    with urllib.request.urlopen(req_login) as resp:
        login_html = resp.read().decode("utf-8")
        log_step("GET /login (SSO Portal UI)", resp.status == 200 and "Meikova ID" in login_html)

    req_reg = urllib.request.Request(f"{base_url}/register")
    with urllib.request.urlopen(req_reg) as resp:
        reg_html = resp.read().decode("utf-8")
        log_step("GET /register (SSO Portal UI)", resp.status == 200 and "Tạo tài khoản" in reg_html)

    # 2. Key Export & JWKS
    code, body = http_request(f"{base_url}/api/auth/keys")
    log_step("GET /api/auth/keys", code == 200 and "public_key_pem" in body, f"Alg: {body.get('algorithm')}, JWKS keys: {len(body.get('jwks', {}).get('keys', []))}")

    code, body = http_request(f"{base_url}/.well-known/jwks.json")
    log_step("GET /.well-known/jwks.json", code == 200 and "keys" in body, f"Keys: {len(body.get('keys', []))}")

    # 3. Registration (Centralized)
    ts = int(time.time())
    test_username = f"meikova_test_{ts}"
    test_email = f"meikova_{ts}@meikova.io"
    test_password = "MeikovaSecretPassword123"

    reg_payload = {
        "username": test_username,
        "password": test_password,
        "email": test_email,
        "display_name": "Titan Test Master"
    }
    code, body = http_request(f"{base_url}/api/auth/register", method="POST", data=reg_payload)
    user_id = body.get("user", {}).get("id")
    token = body.get("token")
    log_step("POST /api/auth/register (New User)", code == 201 and bool(token), f"User ID: {user_id}, Token Issued: {bool(token)}")

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
    code, me_body = http_request(f"{base_url}/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    me_user = me_body.get("user", {})
    log_step("GET /api/auth/me (Bearer Token)", code == 200 and me_user.get("id") == user_id, f"Username: {me_user.get('username')}, Role: {me_user.get('role')}")

    # 12. Google OAuth 1-Click Login / Auto-Provisioning
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

    # 13. Google OAuth Deduplication / Link
    code, g_body2 = http_request(f"{base_url}/api/auth/google", method="POST", data={"credential": fake_google_id_token})
    log_step("POST /api/auth/google (Identity Link Deduplication)", code == 200 and g_body2.get("user", {}).get("id") == g_user_id, f"Deduplicated to User ID: {g_body2.get('user', {}).get('id')}")

    # 14. Tampered Token Rejection
    tampered_token = (token or "dummytoken12345678")[:-4] + "AAAA"
    code, _ = http_request(f"{base_url}/api/auth/verify?token={tampered_token}")
    log_step("Tampered Token Rejection (Verify API)", code == 401, f"Code: {code}")

    code, _ = http_request(f"{base_url}/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    log_step("Tampered Token Rejection (Me API)", code == 401, f"Code: {code}")

    # 15. Expired Token Rejection
    expired_token = issue_universal_token(user_id="usr_expired", username="expired_user", expires_in_sec=-3600)
    code, _ = http_request(f"{base_url}/api/auth/verify?token={expired_token}")
    log_step("Expired Token Rejection (Verify API)", code == 401, f"Code: {code}")

    # 16. Missing Token Rejection
    code, _ = http_request(f"{base_url}/api/auth/me")
    log_step("Missing Token Rejection", code == 401, f"Code: {code}")

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
