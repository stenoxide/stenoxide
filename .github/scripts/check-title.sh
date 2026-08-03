#!/usr/bin/env bash
#
# Checks that a pull request title is a Conventional Commit.
#
# Usage: check-title.sh "<title>"
#
# The title is not cosmetic. A squashed merge writes it as the subject of the
# commit that lands on the branch, and when the squash body carries no list of
# the commits it replaced, that subject is the only thing the release job has to
# work from: it decides the version bump and it is the changelog entry.

set -euo pipefail

title=${1:-}

types='feat|fix|chore|docs|refactor|perf|style|test|build|ci|revert'

# A trailing `(#123)` is what GitHub appends when it squashes, so a title that
# already carries one is still valid.
if [[ $title =~ ^(${types})(\([a-z0-9._-]+\))?!?:[[:space:]]+[^[:space:]] ]]; then
    echo "Title is a Conventional Commit: $title"
    exit 0
fi

cat >&2 <<EOF
The pull request title is not a Conventional Commit.

  Got:      $title
  Expected: <type>[(scope)][!]: <description>

Accepted types, and what each one does to the version:

  feat            minor bump
  fix             patch bump
  chore, docs, refactor, perf, style, test, build, ci, revert
                  patch bump
  any type with ! before the colon
                  major bump, as does a "BREAKING CHANGE:" footer in the body

Examples:

  feat(cli): read the payload from a file
  fix(core): off-by-one in the capacity check
  refactor(stego)!: rework the permutation seed
EOF
exit 1
