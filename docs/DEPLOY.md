<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Secure deployment and rollback

## Prerequisites

A compatible SuiteCRM instance with an HTTPS URL and API v8, Docker Compose,
a configured reverse proxy for the narrowly scoped OAuth routes, and an
authorized OpenAI Secure MCP Tunnel are required.

Development and deployment tooling use PHP 8.5 and Composer 2. PHP 8.6
prereleases are tested separately and are not the production runtime.

The root Composer lock contains the production dependencies and the Composer
bin plugin. PHPUnit, PHPStan, and PHP-CS-Fixer dependencies are installed in
independent `vendor-bin/<tool>/` directories and are excluded from the runtime
image. See [engineering quality](QUALITY.md) for the isolated tool commands.

## 1. Set up your SuiteCRM OAuth client

Create a **confidential Authorization Code** OAuth client in your existing
HTTPS SuiteCRM installation. Set its redirect URI to
`<MCP_OAUTH_ISSUER>/callback`, for example
`https://crm.example.com/suitecrm-mcp-auth/callback`.

## 2. Configure your installation privately

Copy `.env.deploy.example` to `.env.deploy` and configure your own:

- `SUITECRM_BASE_URL`: full HTTPS base URL (optional application subpath).
- `SUITECRM_AUTH_CLIENT_ID` and the file holding its secret.
- `MCP_OAUTH_ISSUER`: HTTPS issuer on the same public host with one path segment.
- `MCP_OAUTH_ORIGIN`: the issuer's scheme + hostname, without a path. Required
  to restrict tunnel-client OAuth discovery.
- `MCP_OAUTH_EDGE_ALIAS`: the internal DNS alias used by your HTTPS reverse
  proxy to reach oauth-edge.
- `MCP_OAUTH_CLIENT_ID` and `MCP_OAUTH_REDIRECT_URI`: registered ChatGPT client.
- `OPENAI_TUNNEL_ID`, `MCP_RESOURCE_URI`: the tunnel's exact hosted resource.
- `APP_UID`, `APP_GID`, `MCP_PROXY_NETWORK`: local Docker permissions/network.
- `MCP_ALLOWED_HOSTS`: accepted **private MCP** transport hostnames.

Put keys and confidential OAuth secrets in restricted `secrets/` files; do not
store them in Git, screenshots, issues, PR descriptions or console history.
The token encryption key is 32 random bytes encoded in base64. **Never replace
an existing key without a controlled credential migration.**

The existing HTTPS reverse proxy forwards only the four exact routes listed
in [authentication](AUTH.md), using the documented proxy example. The OAuth
edge shares the proxy's Docker network but publishes no host port.

## 3. Test without a real CRM

```sh
composer install
composer bin all install
make check
make audit
make smoke
```

The smoke test creates temporary **synthetic** credentials, builds ephemeral
containers, verifies that the private MCP requires authentication, that OAuth
metadata is correct, and that public-only access excludes internal endpoints.
It must never connect to production SuiteCRM.

## 4. Release

Use the reviewed source and a tagged, security-patched stable PHP image.
Create a consistent snapshot of all three SQLite files **and** securely back
up the decryption key, then record the previous Docker image ID.

```sh
docker compose --profile chatgpt --profile oauth-edge \
  --env-file .env.deploy config --quiet
docker compose --profile chatgpt --profile oauth-edge \
  --env-file .env.deploy up -d --build app
docker compose --profile chatgpt --profile oauth-edge \
  --env-file .env.deploy ps
```

Validate private health, public OAuth metadata, unauthorized MCP rejection,
a real personal `crm_whoami` and minimally scoped read-only record lookups.
Confirm commercial write flags remain `false`. No production writes are needed
for verification.

For a prior deployment, preserve `MCP_OAUTH_ISSUER` and the DNS alias from the
existing installation; do not modify the reverse proxy callback paths unless
a coordinated OAuth migration is planned.

## 5. Revoke an account

```sh
docker compose --env-file .env.deploy exec -T app \
  php /app/bin/user-access.php --confirm revoke '<TEST_USER_UUID>'
docker compose --env-file .env.deploy exec -T app \
  php /app/bin/user-access.php --confirm unblock '<TEST_USER_UUID>'
```

Use authorized test identities first. Unblocking requires a fresh personal
OAuth login. Never perform a revocation test on your sole administrator or
only active operational account.

## 6. Rollback

Restoring an older runtime which ignores session revocation is **unsafe**
after an identity has been revoked. In this case, halt the tunnel and fix the
newer runtime; do not silently downgrade authorization checks.

Never overwrite a currently valid token database with a stale backup during
a routine code rollback. Test a full recovery only in an isolated environment.


## Preparing a source release

From a clean, reviewed Git checkout, run `make release VERSION=<VERSION>`.
The target wraps `git archive` and prints the resulting SHA256 checksum,
rather than maintaining a custom tar allowlist or reading live secrets.
The resulting artifact contains only Git-tracked source files and must be
inspected prior to publication.
