---
name: suitecrm-mcp-maintenance
description: "Maintain and review the reusable SuiteCRM PHP MCP: OAuth, ACLs, tools, tests, Composer bin isolation, Docker and GitHub quality workflows."
---

<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Maintain SuiteCRM MCP

1. Read `AGENTS.md` and `docs/SECURITY.md`, then the affected source and tests.
2. Use PHP 8.5 stable, Composer 2, and the official PHP `mcp/sdk`.
   PHP 8.6 prerelease builds are for separate preview compatibility checks.
3. Maintain production dependencies in the root Composer lock; use distinct
   `vendor-bin/phpunit`, `vendor-bin/phpstan`, and
   `vendor-bin/php-cs-fixer` locks for tools.
4. Every tool must enforce typed inputs, pagination and field restrictions,
   personal SuiteCRM identity and ACLs, with negative regression coverage.
5. Never allow arbitrary URLs, SQL queries, shared admin credentials, or an
   actor-supplied identity.
6. Writes remain gated behind independent cryptographic human approval.
7. Run appropriate Composer checks, Docker build and synthetic HTTP smoke.
8. Document what passed locally, what was validated via an actual connector,
   and what still requires user acceptance.
9. Update English documentation and SPDX headers on every relevant change.
10. Never display or version real environment configuration, encrypted state,
    secret keys, token strings, or CRM business data.

Report changed files, validation evidence, security implications, and any
remaining unsupported behavior.
