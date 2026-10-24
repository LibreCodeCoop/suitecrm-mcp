<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Agent instructions

Read the README, deployment documentation, and nearby tests first. This is a
**reusable** SuiteCRM MCP server, not an organization-specific deployment.

## Security rules

- Never read, print, log, or commit `.env`, `.env.deploy`, `secrets/`,
  `var/`, CRM business records, tokens or OAuth authorization codes.
- Individual SuiteCRM OAuth credentials are mandatory. Never add an admin
  credential fallback or accept a client-provided user identifier.
- Backend authorization, ACLs, revocation, field restrictions and human
  approvals must not be replaced with chat prompts or frontend checks.
- Do not execute production CRM writes while testing; draft tools never write.
  Hide the execution tool unless *both* backend write gates are enabled.
- Do not publish `/mcp`, internal `/oauth/token`, `/healthz`, or private data.
- Validate HTTPS issuer/host and OAuth resource against private configuration.
  Public source files must use example hostnames and synthetic IDs.
- Commercial changes require signed independent approval for the exact change,
  with separate review of SuiteCRM automation side effects.

## Development workflow

- PHP 8.5 is the production target; PHP 8.6 RC is preview-only.
- Runtime packages belong in root Composer. PHPUnit, PHPStan, and code style
  tools belong in distinct `vendor-bin/` namespaces.
- Run `make check`, `make audit` and `make smoke` when relevant. Prefer
  black-box behavior tests; test security failures as well as success.
- Use focused PRs, Conventional Commits, DCO `Signed-off-by` and Git signatures.
- Add SPDX headers to files which support comments. The REUSE metadata must
  enumerate only **explicit, comment-incapable exceptions**; never `**`.
- Preserve compatibility with installed identities and encrypted state during
  upgrades. Never deploy a prerelease PHP runtime to production.


## Docker image changes

Do not add unpinned external image references. Keep literal release versions
and full SHA256 manifest digests together in Dockerfile, Compose, and any CI
preview images. Independently check the version/digest mapping at the registry.
Renovate exclusively updates Dockerfile and Docker Compose images. Dependabot
updates Composer and GitHub Actions only. Never overlap image managers or
create a custom digest update job. Keep Docker smoke tests in
`tests/integration/` and avoid rewriting host Docker/Git orchestration in PHP.
