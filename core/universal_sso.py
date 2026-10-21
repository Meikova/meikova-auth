# -*- coding: utf-8 -*-
"""
Meikova Platform — Universal SSO & Auth Module (Ed25519)
Self-contained, production-ready module for Meikova Auth Gateway.
Supports loading keys from environment variables (Render/Cloud) or local files.
"""

import os
import time
import json
import base64
from pathlib import Path
from typing import Optional, Dict, Any

CORE_DIR = Path(__file__).resolve().parent
AUTH_ROOT = CORE_DIR.parent
KEYS_DIR = AUTH_ROOT / "keys"

DEFAULT_PUB_KEY = KEYS_DIR / "ed25519_public.pem"
DEFAULT_PRIV_KEY = KEYS_DIR / "ed25519_private.pem"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


class UniversalSSO:
    def __init__(self, public_key_path: str = None, private_key_path: str = None):
        # 1. Try environment variables (Render / Cloud Native)
        env_priv = os.environ.get("AUTH_PRIVATE_KEY_PEM")
        if not env_priv and os.environ.get("AUTH_PRIVATE_KEY_B64"):
            try:
                env_priv = base64.b64decode(os.environ["AUTH_PRIVATE_KEY_B64"]).decode("utf-8")
            except Exception:
                pass

        env_pub = os.environ.get("AUTH_PUBLIC_KEY_PEM")
        if not env_pub and os.environ.get("AUTH_PUBLIC_KEY_B64"):
            try:
                env_pub = base64.b64decode(os.environ["AUTH_PUBLIC_KEY_B64"]).decode("utf-8")
            except Exception:
                pass

        # 2. Fallback to local files
        pub_path = Path(public_key_path) if public_key_path else DEFAULT_PUB_KEY
        priv_path = Path(private_key_path) if private_key_path else DEFAULT_PRIV_KEY

        self.private_key_pem = env_priv or (priv_path.read_text(encoding="utf-8") if priv_path.exists() else None)
        self.public_key_pem = env_pub or (pub_path.read_text(encoding="utf-8") if pub_path.exists() else None)

    def issue_token(
        self,
        user_id: str,
        username: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        role: str = "user",
        expires_in_sec: int = 30 * 86400,
    ) -> str:
        """Issues an Ed25519-signed universal JWT token valid for 30 days."""
        if not self.private_key_pem:
            raise ValueError("Private key not configured for issuing SSO tokens.")

        now = int(time.time())
        header = {"alg": "EdDSA", "typ": "JWT"}
        payload = {
            "iss": "meikova.auth",
            "sub": str(user_id),
            "username": str(username),
            "email": str(email) if email else None,
            "display_name": str(display_name or username),
            "role": str(role),
            "iat": now,
            "exp": now + expires_in_sec,
        }

        h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{h_b64}.{p_b64}".encode("utf-8")

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            priv = serialization.load_pem_private_key(self.private_key_pem.encode("utf-8"), password=None)
            sig = priv.sign(signing_input)
        except ImportError:
            from Cryptodome.PublicKey import ECC
            from Cryptodome.Signature import eddsa
            key = ECC.import_key(self.private_key_pem)
            signer = eddsa.new(key, "rfc8032")
            sig = signer.sign(signing_input)

        sig_b64 = _b64url_encode(sig)
        return f"{h_b64}.{p_b64}.{sig_b64}"

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verifies token offline in ~0.1ms using Ed25519 public key.
        Returns payload dict if valid and unexpired, None otherwise.
        """
        if not token or not self.public_key_pem:
            return None

        parts = token.strip().split(".")
        if len(parts) != 3:
            return None

        h_b64, p_b64, sig_b64 = parts

        try:
            sig = _b64url_decode(sig_b64)
            signing_input = f"{h_b64}.{p_b64}".encode("utf-8")

            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import ed25519
                pub = serialization.load_pem_public_key(self.public_key_pem.encode("utf-8"))
                pub.verify(sig, signing_input)
            except ImportError:
                from Cryptodome.PublicKey import ECC
                from Cryptodome.Signature import eddsa
                key = ECC.import_key(self.public_key_pem)
                verifier = eddsa.new(key, "rfc8032")
                verifier.verify(signing_input, sig)

            payload = json.loads(_b64url_decode(p_b64).decode("utf-8"))
            if payload.get("exp", 0) < time.time():
                return None
            return payload
        except Exception:
            return None


# Singleton instance
sso_instance = UniversalSSO()
issue_universal_token = sso_instance.issue_token
verify_universal_token = sso_instance.verify_token
