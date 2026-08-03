#!/usr/bin/env bash
#
# Renders one changelog section from the change list `changes.sh` produces.
#
# Usage: changelog.sh <version> [<repository url>] < changes
#
# The list is read from standard input. The same list decides the version, so a
# section rendered from it can never describe a release the number disagrees
# with.
#
# Each entry is printed as its description, attributed and linked:
#
#     - **cli**: read the payload from a file — Ada Lovelace ([`0794b7d`](…))
#
# What is *not* printed is the Conventional Commit prefix. The type is already
# the heading the entry sits under, so repeating it adds nothing, and the scope
# is only worth a reader's attention when it names a part of the program. Scopes
# that name the process which produced the change rather than the code it
# touched — `prompt-9`, `prompt-12` — are dropped: they mean something to
# whoever ran the work and nothing at all to whoever is reading the release.

set -euo pipefail

version=${1:?usage: changelog.sh <version> [<repository url>] < changes}
repo_url=${2:-}

date=$(date +%Y-%m-%d)

# Populated by `collect`, read by `section`. One pass over the input rather than
# one per heading: the input is a pipe and can only be read once.
declare -A entries=()

format() {
    local line=$1 hash=$2 author=$3
    local scope= description=$line

    if [[ $line =~ ^[a-z]+(\(([^\)]*)\))?!?:[[:space:]]+(.*)$ ]]; then
        scope=${BASH_REMATCH[2]}
        description=${BASH_REMATCH[3]}
    fi

    case $scope in
        prompt | prompt[-_.]*) scope= ;;
    esac

    local prefix=
    [ -n "$scope" ] && prefix="**${scope}**: "

    local short=${hash:0:7}
    local link="\`${short}\`"
    [ -n "$repo_url" ] && link="[\`${short}\`](${repo_url}/commit/${hash})"

    printf -- '- %s%s — %s (%s)\n' "$prefix" "$description" "$author" "$link"
}

while IFS=$'\t' read -r kind line hash author; do
    [ -n "$kind" ] || continue
    entries[$kind]+=$(format "$line" "$hash" "$author")$'\n'
done

section() {
    local kind=$1 heading=$2
    [ -n "${entries[$kind]:-}" ] || return 0
    printf '\n### %s\n%s' "$heading" "${entries[$kind]}"
}

echo "## [$version] - $date"
section breaking "Breaking Changes"
section feat     "Features"
section fix      "Bug Fixes"
section other    "Other Changes"
section deps     "Dependencies"
echo
