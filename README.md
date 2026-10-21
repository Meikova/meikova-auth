# Meikova Auth Gateway & Universal Identity Service

Independent, high-performance Centralized Identity & Universal SSO Gateway for the Meikova Ecosystem (Meikova Relay, Meikova Loop, Meikova Harvest).

## Architecture Highlights

- **Database:** Turso Cloud SQLite (`meikova-auth`) over encrypted libSQL HTTPS pipeline with local SQLite fallback.
- **Universal SSO:** Asymmetric Ed25519 token signatures (30-day lifetime).
- **Zero-Roundtrip Client Verification:** All downstream applications (Relay, Loop, Harvest) verify tokens locally in **0.1ms** using the public key without making HTTP requests to the Gateway.
- **Standard JWKS Keyset:** Exposes RFC 8037 JWKS keyset at `/.well-known/jwks.json` and `/api/auth/keys`.
- **Zero-Dependency Cloud Deploy:** Completely self-contained, no external filesystem dependencies.

---

## Deploy to Render (Cloud Web Service)

### Method 1: Render Blueprint (1-Click via `render.yaml`)
1. Create a GitHub repository for `Meikova/meikova-auth` (or link your repo).
2. On the [Render Dashboard](https://dashboard.render.com), click **New +** -> **Blueprint**.
3. Connect your repository. Render will automatically parse `render.yaml`.
4. Fill in the Secret Environment Variables:
   - `AUTH_TURSO_AUTH_TOKEN`: Your Turso Auth Token.
   - `AUTH_PRIVATE_KEY_B64`: Base64-encoded `ed25519_private.pem`.
   - `AUTH_PUBLIC_KEY_B64`: Base64-encoded `ed25519_public.pem`.
5. Click **Apply**.

---

### Method 2: Manual Web Service on Render Dashboard
1. On the Render Dashboard, click **New +** -> **Web Service**.
2. Connect your Git repository.
3. Configure the service settings:
   - **Name:** `meikova-auth`
   - **Region:** Singapore (or closest to your users)
   - **Branch:** `main`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn server:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path:** `/health`
   - **Plan:** Free
4. In **Environment Variables**, add:

| Key | Value | Note |
| --- | --- | --- |
| `PORT` | `10000` | Render standard port |
| `AUTH_TURSO_DATABASE_URL` | `https://meikova-auth-m3ik18dp.aws-ap-northeast-1.turso.io` | Turso Cloud Database URL |
| `AUTH_TURSO_AUTH_TOKEN` | `eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...` | Turso Database Token |
| `AUTH_PRIVATE_KEY_B64` | `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...` | Base64-encoded private key |
| `AUTH_PUBLIC_KEY_B64` | `LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0...` | Base64-encoded public key |
| `CORS_ORIGINS` | `*` | Or specific domains |

5. Click **Create Web Service**.

---

## API Endpoints

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/` | Service metadata and endpoint index |
| `GET` | `/health` | Healthcheck (database connectivity & key status) |
| `POST` | `/api/auth/register` | Centralized user registration (PBKDF2-SHA256) |
| `POST` | `/api/auth/login` | Login with username/email + password -> Ed25519 JWT |
| `POST` | `/api/auth/google` | 1-Click Google OAuth Identity linking / auto-provisioning |
| `GET` | `/api/auth/me` | Fetch user profile via `Authorization: Bearer <token>` |
| `GET/POST`| `/api/auth/verify` | External client token verification endpoint |
| `GET` | `/api/auth/keys` | Public Key export (PEM and JWKS) |
| `GET` | `/.well-known/jwks.json` | RFC 8037 standard JWKS keyset |

---

## Local Development & Testing

```bash
# Clone and enter project
cd meikova-auth

# Install dependencies
pip install -r requirements.txt

# Run automated test suite
python tests/test_auth_server.py

# Start local server
python server.py --host 0.0.0.0 --port 8990
```
