<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Authentication architecture

## System overview

The MCP endpoint is available through a private tunnel rather than an
internet-facing port. A separate HTTPS route handles the browser-based OAuth
authorization flow.

```text
ChatGPT -- OpenAI Secure MCP Tunnel <-- outbound TLS -- tunnel client
                                                   |
                                             private nginx /mcp
                                                   |
                                              PHP MCP / SQLite
                                                   |
                                           SuiteCRM API v8 / ACL

Browser -- existing HTTPS reverse proxy -- OAuth edge -- PHP OAuth broker
                                           |
                                    SuiteCRM OAuth login
```

The private MCP endpoint does not need its own public DNS name or incoming
host port. An existing HTTPS SuiteCRM domain hosts the configurable OAuth
issuer route. The broker verifies personal SuiteCRM credentials; MCP data
access is restricted by the authenticated account and module/field policy.

The application has two OAuth layers and requires no separate SSO provider.

1. An MCP OAuth authorization server issues short-lived, signed, audience-bound
   MCP access tokens. It uses a configurable issuer, such as
   `https://crm.example.com/suitecrm-mcp-auth`.
2. The MCP broker uses a **confidential OAuth Authorization Code client**
   registered with SuiteCRM to authenticate each person. It calls SuiteCRM's
   `/Api/V8/current-user` to confirm their UUID and stores their access/refresh
   tokens encrypted on the application host.

ChatGPT obtains its MCP token through Authorization Code + PKCE S256 with the
`mcp:read` scope. The protected MCP resource must match exactly
`https://api.openai.com/v1/mcp/<TUNNEL_ID>` in a tunnel deployment.

## Routes

The existing HTTPS proxy must expose exactly:

- `/.well-known/oauth-authorization-server/<ISSUER_SEGMENT>` — GET
- `/<ISSUER_SEGMENT>/authorize` — GET
- `/<ISSUER_SEGMENT>/callback` — GET
- `/<ISSUER_SEGMENT>/token` — POST

The route segment comes from `MCP_OAUTH_ISSUER`; it is not hard-coded.
All other paths, including `/mcp` and the *internal* `/oauth/token`, must
remain unreachable from the public reverse proxy. The internal nginx listener
serves both the private MCP endpoint and the OAuth discovery shim needed by
the tunnel client. PHP enforces that browser-facing requests use the
configured HTTPS issuer host.

## User lifecycle

The token vault stores individual SuiteCRM credentials encrypted with
libsodium. Signed MCP JWTs include an integer session generation. An authorized
operator may run `bin/user-access.php --confirm revoke <USER_UUID>` to delete
the personal link, block reauthorization, revoke refresh tokens and deny
previously issued JWTs. `unblock` permits **new** OAuth login without reviving
old JWTs or credentials.

The operator should also revoke upstream SuiteCRM authorization during
offboarding; this application cannot invalidate OAuth tokens held by the
SuiteCRM server itself.

Only the backend decides the current actor. Never accept a user UUID,
token, or permission claimed by a tool argument as an authorization source.
