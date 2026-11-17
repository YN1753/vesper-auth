# Vesper Auth

Vesper Auth is a lightweight, single-binary OAuth 2.0 / OpenID Connect (OIDC) single sign-on identity provider built for personal cloud infrastructure (`auth.starryheavens.uk`). It operates as a single-administrator controlled system with no public registration.

## Architecture and Capabilities

- **Single Binary**: Go + pure-Go SQLite (`modernc.org/sqlite`, WAL mode with separated writer/reader connection pools, zero CGO) + `embed.FS` content-fingerprinted static assets.
- **Zero External Dependencies**: No Docker, Redis, or external database required.
- **Authentication**:
  - WebAuthn Passkeys (`go-webauthn`, Touch ID / Face ID / Android Passkeys / hardware keys) with Conditional UI autofill and hardware clone detection.
  - Argon2id master password fallback.
  - Sudo Mode re-authentication before high-privilege administrative actions (password change, Passkey removal, client secret reset, client deletion, signing key rotation).
- **Security Hardening**:
  - Strict `Content-Security-Policy` (no inline scripts or inline styles), `Permissions-Policy`, `HSTS`, and persistent SQLite-backed CSRF tokens.
  - Trusted reverse-proxy CIDR boundary (`AUTH_TRUSTED_PROXIES`) paired with Cloudflare edge `real_ip_header` validation in Nginx.
  - Bounded IP + account/client sliding-window rate limiter, `HttpOnly; Secure; SameSite=Lax` sessions, and automatic background SQLite maintenance/GC.
  - Optional asynchronous HMAC-signed security alert webhooks (`AUTH_ALERT_WEBHOOK_URL`) for real-time BotHub notifications.
- **OIDC / OAuth 2.0**:
  - `GET /.well-known/openid-configuration` (CORS enabled)
  - `GET /.well-known/jwks.json` (zero-downtime RS256 key rotation retaining prior public keys)
  - `GET /oauth2/authorize` & `POST /oauth2/authorize` (PKCE `S256`, `trusted` silent consent, `prompt=none|login|consent`, `max_age`, RFC 8252 dynamic loopback port matching for public native clients)
  - `POST /oauth2/token` (`client_secret_basic`, `client_secret_post`, public PKCE clients, `refresh_token` rotation with reuse family revocation, dynamic client Origin CORS)
  - `GET /oauth2/userinfo` & `POST /oauth2/userinfo`
  - `POST /oauth2/introspect` (RFC 7662 Token Introspection)
  - `POST /oauth2/revoke` (RFC 7009 Token Revocation)
  - `GET /oauth2/logout` & `POST /oauth2/logout` (OIDC RP-Initiated Logout with anti-CSRF confirmation)

## Local Build and Verification

```bash
go test -count=1 -race ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o vesper-auth .
```

Run locally for development:

```bash
AUTH_ISSUER=http://127.0.0.1:8090 AUTH_LISTEN=127.0.0.1:8090 AUTH_DB_PATH=./data/auth.db ./vesper-auth
```

## Built-in Maintenance and Emergency CLI

```bash
# Print version information
./vesper-auth version

# Create an online, integrity-verified SQLite snapshot (safe while server is running)
AUTH_DB_PATH=/opt/vesper-auth/data/auth.db ./vesper-auth backup /opt/vesper-auth/backups/auth.db

# Emergency password reset via SSH (also revokes active sessions and OAuth tokens)
AUTH_DB_PATH=/opt/vesper-auth/data/auth.db ./vesper-auth admin reset-password --password "NewStrongPassword123!"

# Inspect or clear registered Passkeys via SSH
AUTH_DB_PATH=/opt/vesper-auth/data/auth.db ./vesper-auth admin list-passkeys
AUTH_DB_PATH=/opt/vesper-auth/data/auth.db ./vesper-auth admin delete-passkey <pk_id|--all>

# Rotate RS256 OIDC signing keypair via SSH
AUTH_DB_PATH=/opt/vesper-auth/data/auth.db ./vesper-auth admin rotate-key
```

## Ubuntu Server Deployment (systemd + Nginx + Cloudflare)

1. Build `linux/amd64` static binary (or download from GitHub Releases):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o vesper-auth-linux-amd64 .
```

2. Prepare system user, directories, and binary on the server:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vesper-auth || true
sudo mkdir -p /opt/vesper-auth/data /etc/vesper-auth
sudo cp vesper-auth-linux-amd64 /opt/vesper-auth/vesper-auth
sudo chmod 0755 /opt/vesper-auth/vesper-auth
sudo chown -R vesper-auth:vesper-auth /opt/vesper-auth
```

3. Configure environment variables:

```bash
sudo cp deploy/vesper-auth.env.example /etc/vesper-auth/vesper-auth.env
sudo chmod 0640 /etc/vesper-auth/vesper-auth.env
sudo chown root:vesper-auth /etc/vesper-auth/vesper-auth.env
```

4. Install and start the `systemd` service:

```bash
sudo cp deploy/vesper-auth.service /etc/systemd/system/vesper-auth.service
sudo systemctl daemon-reload
sudo systemctl enable --now vesper-auth
sudo systemctl status vesper-auth
```

5. Configure Nginx on port 80 using `deploy/nginx-auth.starryheavens.uk.conf` (TLS terminated at Cloudflare edge, validating Cloudflare edge CIDRs via `set_real_ip_from`).

## Client Integration Notes

- **Discovery URL**: `https://auth.starryheavens.uk/.well-known/openid-configuration`
- **Nezha (`dash.starryheavens.uk`)**: Client ID `nezha`, callback `https://dash.starryheavens.uk/oauth2/callback`.
- **Alist (`pan.starryheavens.uk`)**: Client ID `alist`, callback `https://pan.starryheavens.uk/api/auth/sso_callback`.
- **BotHub 2.0 Web (`bot.starryheavens.uk`)**: Client ID `bothub-web`, confidential client with PKCE enabled.
- **BotHub 2.0 Android**: Client ID `bothub-android`, public client (`is_public=true`, `pkce_required=true`) with custom URI scheme or loopback callback and `offline_access` scope.
