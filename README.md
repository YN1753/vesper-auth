# Vesper Auth

Vesper Auth is a lightweight, single-binary OAuth 2.0 / OpenID Connect (OIDC) single sign-on identity provider built for personal cloud infrastructure (`auth.starryheavens.uk`). It operates as a single-administrator controlled system with no public registration.

## Architecture and Stack

- **Single Binary**: Go + pure-Go SQLite (`modernc.org/sqlite`, WAL mode, zero CGO) + `embed.FS` frontend assets.
- **Zero External Dependencies**: No Docker, Redis, or external database required.
- **Authentication**: WebAuthn Passkeys (`go-webauthn`, Touch ID / Face ID / Android Passkeys / hardware keys) as primary login, with Argon2id master password fallback.
- **Security**: IP + account/client rate limiting, `HttpOnly; Secure; SameSite=Lax` sessions with remote revocation, CSRF validation, and persistent SQLite audit logs.
- **OIDC / OAuth 2.0**:
  - `GET /.well-known/openid-configuration`
  - `GET /.well-known/jwks.json` (persistent 2048-bit RSA keypair, `RS256`)
  - `GET /oauth2/authorize` & `POST /oauth2/authorize` (PKCE `S256`, `trusted` silent consent bypass)
  - `POST /oauth2/token` (`client_secret_basic`, `client_secret_post`, public PKCE clients, `refresh_token` rotation with reuse family revocation)
  - `GET /oauth2/userinfo` & `POST /oauth2/userinfo`
  - `POST /oauth2/revoke`
  - `GET /oauth2/logout` & `POST /oauth2/logout`

## Local Build and Verification

```bash
go test ./...
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o vesper-auth .
```

Run locally for development:

```bash
AUTH_ISSUER=http://127.0.0.1:8090 AUTH_LISTEN=127.0.0.1:8090 AUTH_DB_PATH=./data/auth.db ./vesper-auth
```

Open `http://127.0.0.1:8090` to complete the first-boot `/setup` flow (or set `AUTH_ADMIN_PASSWORD` in environment variables before startup).

## Ubuntu Server Deployment (systemd + Nginx)

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

5. Configure Nginx on port 80 using `deploy/nginx-auth.starryheavens.uk.conf` (TLS terminated at Cloudflare edge, forwarding `X-Forwarded-Proto` and `CF-Connecting-IP`).

## Client Integration Notes

- **Discovery URL**: `https://auth.starryheavens.uk/.well-known/openid-configuration`
- **Nezha (`dash.starryheavens.uk`)**: Add a client with callback `https://dash.starryheavens.uk/oauth2/callback`.
- **Alist (`pan.starryheavens.uk`)**: Add a client with callback `https://pan.starryheavens.uk/api/auth/sso_callback`.
- **BotHub 2.0 Web (`bot.starryheavens.uk`)**: Confidential client with PKCE enabled.
- **BotHub 2.0 Android**: Public client (`is_public=true`, `pkce_required=true`) with custom URI scheme callback and `offline_access` scope for Refresh Token rotation.
