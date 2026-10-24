<!--
SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
-->
# Engineering quality

The runtime dependency graph lives in root `composer.json` / `composer.lock`.
The development suites are isolated using `bamarni/composer-bin-plugin`:

- `vendor-bin/phpunit/` — PHPUnit 13.
- `vendor-bin/phpstan/` — PHPStan 2.
- `vendor-bin/php-cs-fixer/` — PHP-CS-Fixer 3.

Each directory tracks its own manifest and lockfile; generated vendor trees
are ignored. CI executes the relevant bin for each separate workflow.

Checks are independent: PHP lint, PHPUnit 8.5, PHPStan, PHP-CS-Fixer,
Composer audit (all locks), Docker smoke, DCO, Conventional Commits,
REUSE, actionlint, Zizmor, and experimental PHP 8.6 compatibility.

Private repositories may require an organization subscription to enforce
branch protection; successful checks alone do not prevent direct pushes.

Release criteria: no production endpoints or tokens in tracked files or
reachable history, tested negative authorization, synthetically tested
Docker topology, and a safe backup/rollback plan.


## Immutable container image policy

Dockerfile and Compose references must use a fully qualified version plus an
OCI multi-platform manifest digest, such as `name:1.2.3@sha256:<digest>`.
Builds always resolve the digest; the tag makes the software version legible
during review. Verify that both identify the same upstream image.

Dependabot manages runtime and build dependencies without overlapping:
`docker` is for the Dockerfile, and `docker-compose` is for Compose services.
The production PHP image is a literal `FROM` because variable-based
`FROM` image names are not reliably recognized by Dependabot.

The build uses only normal Dockerfile instructions, so the floating
`# syntax=docker/dockerfile:1` frontend was removed. PHP 8.6 preview uses
a distinct pinned RC image in CI only.

## Host automation policy

Keep application behavior in PHP. Use POSIX shell only for thin wrappers
around Git and Docker when the commands must run *on the host*, not within
the PHP runtime. The integration smoke still needs lifecycle management,
synthetic secret generation and reliable teardown; it is a test, not a product
runtime tool. The Git sign-off validator does not need a PHP dependency.
Source archives come from `git archive` (via a Makefile target).

**Updater caveat:** Dependabot has documented limitations with Dockerfiles
containing more than one `FROM`. Confirm that both Composer and PHP stages
receive version and digest updates. Until verified, never interpret an
unchanged second stage as evidence that no updates are available. If this
cannot be resolved with Dependabot, use exactly one non-overlapping Docker
update manager and track the organization policy change separately.
