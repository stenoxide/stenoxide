#!/usr/bin/env bash
#
# Derives a Conventional Commit prefix from the changes a pull request carries
# and prints the title it should have.
#
# Usage: fix-title.sh <base sha> "<title>"
#
# The prefix is taken from the most significant change in the range, not
# guessed: the same list that the release job reads to compute the version. A
# title repaired this way therefore cannot disagree with what gets published.

set -euo pipefail

base=${1:?usage: fix-title.sh <base sha> "<title>"}
title=${2:?usage: fix-title.sh <base sha> "<title>"}

changes=$(bash "$(dirname "$0")/changes.sh" "${base}..HEAD")

kind=
entry=
for candidate in breaking feat fix other deps; do
    found=$(awk -F'\t' -v k="$candidate" '$1 == k { print $2; exit }' <<<"$changes")
    if [ -n "$found" ]; then
        kind=$candidate
        entry=$found
        break
    fi
done

if [ -z "$entry" ]; then
    echo "fix-title.sh: the range carries no Conventional Commit to derive a type from" >&2
    exit 1
fi

# Everything up to the scope, the bang or the colon, whichever comes first.
type=${entry%%[(:!]*}

if [ "$kind" = breaking ]; then
    type="${type}!"
fi

printf '%s: %s\n' "$type" "$title"
