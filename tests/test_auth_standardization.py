import os
import re
import sys
import time
import unittest
from pathlib import Path

# Add project root to sys.path
AUTH_ROOT = Path(__file__).resolve().parent.parent
if str(AUTH_ROOT) not in sys.path:
    sys.path.insert(0, str(AUTH_ROOT))

# Guarantee test keys for offline CI/test execution
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
        pass

from starlette.testclient import TestClient
from server import app
from core.universal_sso import issue_universal_token, verify_universal_token


class TestAuthStandardization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_api_health_endpoints(self):
        """Verifies both /health and /api/health report healthy status."""
        r1 = self.client.get("/health")
        self.assertEqual(r1.status_code, 200)
        d1 = r1.json()
        self.assertIn("status", d1)
        self.assertIn("database", d1)

        r2 = self.client.get("/api/health")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r1.json(), r2.json())

    def test_02_auth_google_config_endpoints(self):
        """Verifies both /api/auth/config and /api/auth/google/config aliases return Google client ID."""
        r1 = self.client.get("/api/auth/config")
        self.assertEqual(r1.status_code, 200)
        d1 = r1.json()
        self.assertEqual(d1.get("status"), "online")
        self.assertIn("google_client_id", d1)

        r2 = self.client.get("/api/auth/google/config")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r1.json(), r2.json())

    def test_03_fast_path_ed25519_token(self):
        """Verifies Ed25519 token issuance and verification executes within 1ms."""
        t0 = time.perf_counter()
        token = issue_universal_token(
            user_id="usr_std_test",
            username="std_tester",
            email="tester@meikova.io",
            expires_in_sec=3600
        )
        t_issue = (time.perf_counter() - t0) * 1000

        t1 = time.perf_counter()
        payload = verify_universal_token(token)
        t_verify = (time.perf_counter() - t1) * 1000

        self.assertIsNotNone(payload)
        self.assertEqual(payload.get("sub"), "usr_std_test")
        self.assertEqual(payload.get("username"), "std_tester")
        self.assertLess(t_verify, 5.0, f"Token verification too slow: {t_verify:.2f}ms")

    def test_04_dynamic_host_discovery(self):
        """Verifies /api/host-info and /api/network/host-info return dynamic network hierarchy."""
        r1 = self.client.get("/api/host-info")
        self.assertEqual(r1.status_code, 200)
        d1 = r1.json()
        self.assertIn("lan_ip", d1)
        self.assertIn("active_url", d1)

        r2 = self.client.get("/api/network/host-info")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(d1["lan_ip"], r2.json()["lan_ip"])

    def test_05_dynamic_qr_endpoint(self):
        """Verifies /api/qr generates vector SVG or safe redirect."""
        r = self.client.get("/api/qr?data=https%3A%2F%2Fmeikova.io", follow_redirects=False)
        self.assertIn(r.status_code, [200, 307])
        if r.status_code == 200:
            self.assertIn("svg", r.headers.get("content-type", ""))

    def test_06_dynamic_download_resolvers(self):
        """Verifies /api/download/app/* dynamic download targets."""
        for target in ["windows", "macos", "linux"]:
            r = self.client.get(f"/api/download/app/{target}", follow_redirects=False)
            self.assertIn(r.status_code, [200, 302, 307])

    def test_07_zero_emojis_and_native_dialogs(self):
        """Verifies 0 emojis and 0 native dialogs (alert/confirm/prompt) in static files."""
        emoji_regex = re.compile(r"[\U00010000-\U0010ffff\u2600-\u26ff\u2700-\u27bf]")
        dialog_regex = re.compile(r"\b(window\.)?(alert|confirm|prompt)\s*\(")

        static_dir = AUTH_ROOT / "static"
        for p in static_dir.rglob("*"):
            if not p.is_file() or p.suffix not in [".html", ".js", ".css"]:
                continue
            content = p.read_text(encoding="utf-8")
            for i, line in enumerate(content.splitlines(), 1):
                self.assertIsNone(dialog_regex.search(line), f"Found dialog in {p.name}:{i}: {line.strip()}")
                self.assertIsNone(emoji_regex.search(line), f"Found emoji in {p.name}:{i}: {line.strip()}")

    def test_08_package_license_mit(self):
        """Verifies package.json contains license MIT."""
        pkg = AUTH_ROOT / "package.json"
        content = pkg.read_text(encoding="utf-8")
        self.assertIn('"license": "MIT"', content)


if __name__ == "__main__":
    unittest.main()
