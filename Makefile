# SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
.PHONY: help install test lint cs-check cs-fix analyse audit smoke check release

help:
	@printf "install test lint cs-check cs-fix analyse audit smoke check release\n"
install:
	composer install --no-interaction --prefer-dist
	composer bin all install --no-interaction --prefer-dist
test:
	composer test
lint:
	composer lint
cs-check:
	composer cs:check
cs-fix:
	composer cs:fix
analyse:
	composer analyse
audit:
	composer audit --locked
	composer bin all audit --locked
smoke:
	bash tests/integration/docker-smoke.sh
check:
	composer check

# Only committed, tracked source belongs in a release archive. No working-tree
# files, local secrets, runtime SQLite data or staging artifacts are included.
VERSION ?=
release:
	@test -n "$(VERSION)" || { echo "Usage: make release VERSION=x.y.z" >&2; exit 2; }
	@test -z "$$(git status --porcelain)" || { echo "Commit changes before packaging" >&2; exit 2; }
	@mkdir -p dist
	@test ! -e "dist/suitecrm-mcp-$(VERSION).tar.gz" || { echo "Release archive already exists" >&2; exit 2; }
	git archive --format=tar.gz --prefix=suitecrm-mcp/ --output="dist/suitecrm-mcp-$(VERSION).tar.gz" HEAD
	@sha256sum "dist/suitecrm-mcp-$(VERSION).tar.gz"
