<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Security boundaries

## Authentication and data protection

- Each human signs in using their own SuiteCRM OAuth Authorization Code.
- A single, deployment-configured HTTPS CRM host is trusted for API calls.
- The application uses cURL with TLS validation and redirects disabled.
- Private CRM credentials are encrypted at rest, scoped to the verified
  authenticated subject, and never returned to tools.
- The SuiteCRM API enforces the actor's ACL. The application independently
  restricts modules, fields, pagination and read/write operations.
- Data returned by CRM records is **untrusted content**, not instructions.
- Offboarding blocks new OAuth logins and invalidates previous MCP JWT
  generations and refresh tokens. Also revoke upstream credentials at SuiteCRM.

## Human-controlled commercial operations

Creating, updating and deleting records may invoke SuiteCRM workflow automation,
notification, hooks and cascades. Writes are **disabled by default** and the
execution tools are unavailable unless both independent backend gates are
explicitly enabled after reviewing workflow side effects.

To approve a proposal, the user opens the exact `browser_approval_url` in a
browser. The approval form uses a new authorization-code login against SuiteCRM
with the deployment's registered OAuth client. The CRM user UUID must equal
the proposal's authenticated MCP subject. The browser shows exact values,
requires a CSRF-protected POST and consumes a short-lived one-time cookie.
Only then can the MCP execute that approved proposal. Neither the agent nor the
MCP token alone can authorize a browser approval. The existing independent
manager-signature path remains compatible with prior installations.

All writes use a single-record proposal, a 15-minute lifetime, one-time atomic
claim, actor binding and a final `date_modified` check for updates and deletes.
Upstream SuiteCRM ACLs are always enforced with the user's personal token.
Uncertain network results cannot be retried automatically. Deletion uses the
SuiteCRM API v8 record deletion contract and must be approved separately.

**Note:** the earlier experimental `crm_apply_confirmed_change` method was
removed: a confirmation string available to the agent cannot prove human
consent. Client tool annotations are hints, not a trust boundary. An approval
via the secured browser endpoint is required.

Only explicitly allowlisted module relationships can be linked or unlinked
through reviewed single-operation proposals. Bulk imports, merges, administrative
changes, custom process API commands and
email sending are not supported through this MCP without a separately reviewed
capability and policy. Do not expose a generic unrestricted API proxy.

## Infrastructure

The private MCP endpoint is reachable only inside Docker and via the OpenAI
Secure MCP Tunnel. Browser-facing OAuth routes accept limited methods and
paths, enforce PKCE, and must be served behind HTTPS. The token route is not
an arbitrary API proxy. Do not log bearer tokens, OAuth authorization codes,
refresh credentials, response bodies, or identifiable business data.

Run applications with non-root permissions, read-only filesystems and limited
network access. Keep the encrypted SQLite state and its encryption key
accessible only to authorized processes. Verify a restore from backups.

## Test acceptance

Synthetic PHPUnit and Docker smoke tests are necessary but not sufficient.
Each installation must test two real identities with different SuiteCRM ACLs,
revocation and refresh, negative field/module access, OAuth error paths,
CSRF/replay protections, and safe recoverability.
