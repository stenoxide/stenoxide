#!/usr/bin/env bash
#
# Applies a list of changes to a version, one bump per change, in order.
#
# Usage: next-version.sh <base version>  < changes
#
# The list is read from standard input in the format `changes.sh` produces. The
# bumps are applied iteratively rather than collapsed into the single highest
# one, so the version records how much happened, not only what the most
# significant thing was. Starting from 1.2.3:
#
#     fix, fix, fix, feat, fix, breaking, fix, feat, fix
#     1.2.4  1.2.5  1.2.6  1.3.0  1.3.1  2.0.0  2.0.1  2.1.0  2.1.1
#
# Order matters, and is the reason this cannot be a count of each kind: the
# three patches at the front are absorbed by the minor that follows them, while
# the one after it survives.

set -euo pipefail

base=${1:?usage: next-version.sh <base version> < changes}

major=${base%%.*}
rest=${base#*.}
minor=${rest%%.*}
patch=${rest#*.}

case $major$minor$patch in
    *[!0-9]*) echo "next-version.sh: '$base' is not a MAJOR.MINOR.PATCH version" >&2; exit 1 ;;
esac

while IFS=$'\t' read -r kind _; do
    case $kind in
        breaking) major=$((major + 1)); minor=0; patch=0 ;;
        feat)     minor=$((minor + 1)); patch=0 ;;
        fix|other) patch=$((patch + 1)) ;;
        # Dependency bumps are recorded, not versioned. A release made of
        # nothing else leaves the version where it was, and the release job
        # takes that as "there is nothing to publish".
        deps) ;;
        '') ;;
        *) echo "next-version.sh: unknown change kind '$kind'" >&2; exit 1 ;;
    esac
done

echo "${major}.${minor}.${patch}"
