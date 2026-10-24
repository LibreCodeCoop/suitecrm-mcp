<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# ChatGPT plugin integration

Create a private ChatGPT plugin connected to **your** OpenAI Secure MCP Tunnel.
Keep the actual tunnel ID, OAuth client ID, callback, runtime key and SuiteCRM
host in private settings and environment files, not in this repository.

The canonical resource is `https://api.openai.com/v1/mcp/<TUNNEL_ID>`.
Configure an HTTPS issuer such as
`https://crm.example.com/suitecrm-mcp-auth`, register its exact `/callback`
URL as a confidential SuiteCRM OAuth Authorization Code client, and configure
the ChatGPT OAuth client with PKCE S256 and scope `mcp:read`.

Read-only tools query permitted modules and records with a personal credential.
Drafting tools do not execute. Commercial execution is **not advertised**
while either backend write flag is disabled.

Typical use cases include browsing customer and account context from ChatGPT,
reviewing existing opportunities, exploring available record schemas, and
preparing proposed changes for a human to assess. The modules and fields
available to each person depend on their SuiteCRM permissions and the
installation's explicit allowlists. The integration does not grant users
additional CRM privileges.

The application does not automatically approve or apply suggested changes.
See [security](SECURITY.md) for the restrictions on commercial operations.

Test two different CRM users and confirm ACL isolation before sharing.
