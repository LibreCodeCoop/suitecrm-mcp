<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Security policy

Use the repository's private vulnerability reporting feature, if enabled,
or contact its maintainers through a private channel. Do not expose production
CRM records, tokens, OAuth credentials or network details in public issues.

The MCP listener has no published host port. The separate browser-facing
OAuth endpoints are protected by HTTPS, path/method restrictions, issuer-host
validation and PKCE. Commercial writes are disabled by default.

See [security architecture](docs/SECURITY.md) and
[deployment](docs/DEPLOY.md). Never test real commercial changes without
explicit authorization and a dedicated test environment.
