#!/usr/bin/env bash
#
# Renders one changelog section from the change list `changes.sh` produces.
#
# Usage: changelog.sh <version> [<repository url>] [<date>] < changes
#
# The list is read from standard input. The same list decides the version, so a
# section rendered from it can never describe a release the number disagrees
# with.
#
# The date defaults to today, which is what a release wants. It is settable so
# that an already published section can be re-rendered — after a change to this
# script, say — without the rewrite moving the day the release went out.
#
# Each entry is printed as its description, attributed and linked:
#
#     - **cli**: read the payload from a file — [@ada](…) ([`0794b7d`](…))
#
# What is *not* printed is the Conventional Commit prefix. The type is already
# the heading the entry sits under, so repeating it adds nothing, and the scope
# is only worth a reader's attention when it names a part of the program. Scopes
# that name the process which produced the change rather than the code it
# touched — `prompt-9`, `prompt-12` — are dropped: they mean something to
# whoever ran the work and nothing at all to whoever is reading the release.
#
# The author is the GitHub account, linked to its profile, not the name in the
# commit. A name is whatever `user.name` happened to be set to on the machine
# that made the commit; it identifies nobody, links nowhere, and the same person
# can appear under two spellings in one release. Resolving it costs one API call
# per commit, cached, and falls back to the committed name when the account
# cannot be determined — an unlinked email address, or no network.

set -euo pipefail

version=${1:?usage: changelog.sh <version> [<repository url>] [<date>] < changes}
repo_url=${2:-}
date=${3:-$(date +%Y-%m-%d)}

# Populated by `collect`, read by `section`. One pass over the input rather than
# one per heading: the input is a pipe and can only be read once.
declare -A entries=()

# `owner/name`, which is what the API is addressed by. Derived from the URL so
# that the caller has one thing to pass rather than two that could disagree.
slug=${repo_url#*://*/}

# hash -> GitHub login, or the empty string for a hash already looked up and
# found to have no account behind it. A squash contributes one line per commit
# it replaced, all carrying its own hash, so the cache is what keeps a merge of
# twenty commits from making twenty identical requests.
declare -A logins=()

# Answers in `REPLY` rather than on stdout, and so must be called outside a
# command substitution: a subshell would throw the cache away on return and
# every line of a twenty-commit squash would cost its own request.
resolve_login() {
    local hash=$1
    REPLY=

    [ -n "$repo_url" ] || return 0
    if [ -n "${logins[$hash]+set}" ]; then
        REPLY=${logins[$hash]}
        return 0
    fi

    # Never fatal. Attribution is worth an API call, not a failed release: any
    # error here leaves the committed name in place and the section still
    # renders.
    local login
    if ! login=$(gh api "repos/${slug}/commits/${hash}" --jq '.author.login // empty' 2>/dev/null); then
        login=
    fi

    # A failed `gh` reports the error as JSON on standard output, so the exit
    # code is not enough on its own — the error document would otherwise be
    # pasted in as the author's name. Anything not shaped like a handle goes.
    case $login in
        '' | *[!A-Za-z0-9-]*) login= ;;
    esac

    logins[$hash]=$login
    REPLY=$login
}

format() {
    local line=$1 hash=$2 author=$3 login=$4
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

    local credit=$author
    [ -n "$login" ] && credit="[@${login}](https://github.com/${login})"

    printf -- '- %s%s — %s (%s)\n' "$prefix" "$description" "$credit" "$link"
}

while IFS=$'\t' read -r kind line hash author; do
    [ -n "$kind" ] || continue
    resolve_login "$hash"
    entries[$kind]+=$(format "$line" "$hash" "$author" "$REPLY")$'\n'
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
