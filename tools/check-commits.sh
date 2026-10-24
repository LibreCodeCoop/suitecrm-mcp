#!/bin/sh
# SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Verify every human-authored PR commit, not just the final squash message.
set -eu
if [ "$#" -ne 3 ] || { [ "$1" != "--dco" ] && [ "$1" != "--conventional" ]; }; then
  echo "Usage: $0 --dco|--conventional BASE_REF HEAD_REF" >&2
  exit 2
fi
mode="$1"
base=$(git merge-base "$2" "$3")
failed=0
for commit in $(git rev-list --no-merges "$base..$3"); do
  author=$(git show -s --format=%ae "$commit")
  message=$(git show -s --format=%B "$commit")
  subject=$(git show -s --format=%s "$commit")
  if [ "$mode" = "--conventional" ] && ! printf '%s\n' "$subject" | grep -Eq '^(feat|fix|docs|test|refactor|perf|build|ci|chore|revert|style)(\([a-zA-Z0-9_.-]+\))?(!)?: .{3,}$'; then
    printf 'Conventional Commit missing: %s %s\n' "$commit" "$subject" >&2
    failed=1
  fi
  if [ "$mode" = "--dco" ] && ! printf '%s\n' "$message" | awk -v addr="$author" '
    /^Signed-off-by:/ && index($0, "<" addr ">") > 0 { valid=1 }
    END { exit !valid }
  '; then
    printf 'DCO sign-off for commit author <%s> missing: %s\n' "$author" "$commit" >&2
    failed=1
  fi
done
if [ "$failed" -ne 0 ]; then exit 1; fi
echo "Commit policy passed: $mode"
