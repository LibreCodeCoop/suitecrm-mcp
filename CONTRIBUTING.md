<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Contributing

Use a focused pull request, conventional commit messages, and a DCO
`Signed-off-by` trailer in every commit (`git commit -s -S`). Cryptographic Git
commit signing is a separate but recommended measure.

```sh
composer install
composer bin all install
make check
make audit
make smoke
```

Independent GitHub workflows cover PHP syntax, PHPUnit, PHPStan, code style,
Composer audits, Docker smoke, DCO, Conventional Commits, actionlint, Zizmor
and REUSE. Changes to authentication, ACLs, or token state require negative tests.

Do not include real instance addresses, live environment configuration,
credentials, CRM records or generated binaries in commits or PRs. Use
`crm.example.com` and synthetic IDs for examples. Source files supporting
comments must have SPDX headers.
