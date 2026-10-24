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

## No autonomous commercial operations

Creating/updating opportunities, contacts, accounts, tasks, quotes, or notes
may trigger SuiteCRM workflow automation or outgoing notifications. Commercial
writes remain **disabled by default**. The execution tool is not announced
unless both runtime gates are enabled.

Future enablement requires all of the following:

1. An independently reviewed proposal for a *single exact record operation*.
2. A manager signature (Ed25519) produced outside the MCP application host.
3. Verification of the actor, target, expiry, version, digest, and signature.
4. One-time consumption preventing replay and concurrent state confusion.
5. Separate approval of SuiteCRM workflow and notification side effects.
6. Backend checks even if a chat message claims an operation was approved.

No tool may delete, merge, bulk-import, or change administrative CRM settings
without a different, expressly approved design. An uncertain network result
must not trigger an automatic write retry.

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
