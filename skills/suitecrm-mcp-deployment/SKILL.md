---
name: suitecrm-mcp-deployment
description: "Deploy or upgrade the reusable PHP SuiteCRM MCP over the private OpenAI Secure MCP Tunnel while preserving OAuth identity, encrypted state, and strict HTTPS routes."
---

<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Deploy SuiteCRM MCP securely

1. Read `AGENTS.md`, `docs/AUTH.md`, `docs/DEPLOY.md`, and the threat model.
2. Determine the actual deployment root from the operator, never hardcode
   another organization's filesystem, hostname, or Docker network.
3. Preserve existing `.env.deploy`, encrypted `var/`, keys in `secrets/`,
   OAuth issuer and callback during a compatible upgrade.
4. Use each person's SuiteCRM OAuth Authorization Code client, not shared
   admin credentials. No external SSO provider is assumed.
5. Set your private `OPENAI_TUNNEL_ID`, `MCP_RESOURCE_URI`, OAuth client,
   callback, HTTPS issuer, `MCP_OAUTH_ORIGIN` and `MCP_OAUTH_EDGE_ALIAS`.
6. Keep internal `/mcp` and `/oauth/token` off public ports. Configure only
   the four HTTPS OAuth routes at the existing reverse proxy.
7. Run `composer install`, `composer bin all install`, `make check`,
   `make audit`, and `make smoke` using synthetic credentials.
8. Verify OAuth discovery, token exchange, host/resource binding, private MCP
   unauthorized 401, and an authenticated read-only ChatGPT tool.
9. Validate cross-user ACLs, refresh/revocation, rate limits, logs, backups,
   and rollback before exposing the plugin to multiple users.
10. Do not enable commercial write flags; PHP 8.6 release candidates are
    for compatibility testing, not production.

Document tested steps and remaining risks without publishing instance secrets.

All third-party Docker images must have explicit version and SHA256 digests.
