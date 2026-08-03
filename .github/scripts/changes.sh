#!/usr/bin/env bash
#
# Prints the Conventional Commit changes contained in a git range, oldest first,
# one per line, as `<kind><TAB><description>`. `kind` is one of breaking, feat,
# fix, deps or other; it decides both the version bump the change contributes
# and the section it is filed under in the changelog.
#
# Usage: changes.sh [<git range>]
#
# Squashed merges are the reason this is not a single `git log` invocation. A
# squash carries the pull request title in its subject and the subjects of the
# commits it replaced in its body, as a `*` list. Where such a list exists it is
# authoritative and the subject is discarded: the subject summarises the very
# lines below it, and reading both would count the same work twice.

set -euo pipefail

range=${1:-}

types='(feat|fix|chore|docs|refactor|perf|style|test|build|ci|revert)'

# Conventional Commits mandates the space after the colon. Requiring it keeps
# ordinary prose that happens to open with one of the type words out.
conventional="^${types}(\([^)]*\))?!?:[[:space:]]"

classify() {
    if [[ $1 =~ ^[a-z]+(\([^\)]*\))?!:[[:space:]] ]]; then
        echo breaking
    # Dependency bumps carry no version bump of their own. They are generated,
    # they arrive in bulk, and a resolver moving from 0.25.1 to 0.25.2 under the
    # crate is not a change anyone calling it can observe. They are still listed
    # in the changelog. Marking one `!` overrides this, which is the escape
    # hatch for the bump that does break something.
    elif [[ $1 =~ ^[a-z]+\((deps|deps-dev)\):[[:space:]] ]] ||
        [[ $1 =~ :[[:space:]]+bump[[:space:]]+[^[:space:]]+[[:space:]]+from[[:space:]] ]]; then
        echo deps
    elif [[ $1 =~ ^feat(\([^\)]*\))?:[[:space:]] ]]; then
        echo feat
    elif [[ $1 =~ ^fix(\([^\)]*\))?:[[:space:]] ]]; then
        echo fix
    else
        echo other
    fi
}

mapfile -t hashes < <(git log ${range:+"$range"} --reverse --format='%H')

[ ${#hashes[@]} -eq 0 ] && exit 0

for hash in "${hashes[@]}"; do
    message=$(git log -1 --format='%B' "$hash")

    bullets=$(sed -n -E "s/^[[:space:]]*[-*][[:space:]]+(${types}(\([^)]*\))?!?:[[:space:]].*)$/\1/p" \
        <<<"$message" || true)

    if [ -n "$bullets" ]; then
        lines=$bullets
    else
        # Parameter expansion rather than `head -1`: under `pipefail` a reader
        # that closes the pipe early takes the whole pipeline down with it.
        subject=${message%%$'\n'*}
        lines=$(grep -E "$conventional" <<<"$subject" || true)
    fi

    breaking_seen=0

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # The commit that closes a release is bookkeeping, not a change.
        case $line in
            'chore: release v'*) continue ;;
        esac

        kind=$(classify "$line")
        [ "$kind" = breaking ] && breaking_seen=1
        printf '%s\t%s\n' "$kind" "$line"
    done <<<"$lines"

    # A BREAKING CHANGE footer makes the whole commit breaking. It is emitted
    # last on purpose: the major bump then absorbs the smaller bumps its own
    # commit contributed, so one breaking commit moves the version once.
    if [ "$breaking_seen" -eq 0 ]; then
        footers=$(grep -E '^BREAKING CHANGE:[[:space:]]' <<<"$message" || true)
        while IFS= read -r footer; do
            [ -n "$footer" ] || continue
            printf 'breaking\t%s\n' "$footer"
        done <<<"$footers"
    fi
done
