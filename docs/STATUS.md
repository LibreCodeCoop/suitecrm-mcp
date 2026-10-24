<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Project status

This is reusable SuiteCRM MCP software. Deployment-specific evidence belongs
in private operations records, not this repository.

Implemented features include individual SuiteCRM OAuth, OpenAI tunnel access,
an encrypted token vault, session revocation, serialized token refresh,
module/field policies, a disabled-by-default commercial executor, PHP 8.5,
and isolated developer tools under `vendor-bin/`.

Before granting broad access in **any installation**, verify two different
user ACLs, real refresh/revocation, encrypted SQLite backup restoration,
OAuth audience/issuer binding, non-exposure of private listeners, and
the expected module and field permissions.

PHP 8.6 prerelease checks are experimental until PHP 8.6 GA and all
dependencies have been validated. No real deployment-specific tunnel IDs or
CRM addresses are included in version control.


## PHP 8.6 pre-release blockers (October 2026)

PHP 8.6.0RC4 successfully built the runtime image and passed the application's
PHPUnit 13 suite. Full qualification is **not complete**: PHP-CS-Fixer 3.95.27
explicitly reports syntax support only through PHP 8.5, and PHPStan 2 ran into
a native parallel-worker crash on the PHP 8.6 RC image. Keep stable production
on PHP 8.5.12 and reevaluate upstream releases after PHP 8.6 GA.
