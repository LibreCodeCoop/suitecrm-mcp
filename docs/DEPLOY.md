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
Create a consistent snapshot of all four SQLite files **and** securely back
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
When explicitly enabling authenticated interactive writes, first review
actual SuiteCRM workflows and notification side effects and expose only the
exact `/<ISSUER_SEGMENT>/approve` route through the existing TLS reverse proxy
using the repository's proxy configuration example. Keep the existing OAuth
callback URI and token stores unchanged. Set both `MCP_ALLOW_WRITES=true` and
`MCP_WORKFLOWS_REVIEWED=true` only after these checks and confirm that the
browser review page rejects mismatched CRM identities and missing CSRF tokens.
No real customer record should be written during deployment verification;
use a clearly named disposable synthetic account only with explicit operator
approval, then verify its deletion and re-query the record.

Until all gates have been reviewed, leave commercial write flags `false`.


### Replacing the private nginx or updating the tunnel

The tunnel must never share nginx's container network namespace. Instead, both
join an internal `mcp_transport` network, while the tunnel uses a separate
`tunnel_egress` bridge for outbound HTTPS. The nginx container can be replaced
without restarting the tunnel; its private DNS name remains `nginx`. Neither
network publishes MCP or the generic internal OAuth token endpoint to the host.

When migrating from an older `network_mode: service:nginx` deployment, run the
reviewed Compose file with the existing `.env.deploy` and secrets:

```sh
docker compose --profile chatgpt --profile oauth-edge \
  --env-file .env.deploy config --quiet
# Stop the old namespace-sharing tunnel before replacing its nginx host.
docker compose --profile chatgpt --profile oauth-edge \
  --env-file .env.deploy stop tunnel
docker compose --profile chatgpt --profile oauth-edge \
  --env-file .env.deploy up -d --no-deps nginx tunnel
```

Check that nginx and the tunnel are running and that a personally authenticated
`crm_whoami` succeeds. Subsequent nginx container replacements no longer
require manually recreating the tunnel. Keep the separate OAuth edge untouched
unless its configuration changes. Do not use `docker compose down` during this
migration: it would interrupt unrelated services and may remove networks.

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
