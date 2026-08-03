<!--
The title of this pull request must be a Conventional Commit:

    <type>[(scope)][!]: <description>

CI rejects anything else. The title is not cosmetic: when this is squashed it
becomes the subject of the commit that lands on the branch, and the release
pipeline reads it to compute the version.

    feat        minor bump
    fix         patch bump
    chore, docs, refactor, perf, style, test, build, ci, revert
                patch bump
    a `!` before the colon, or a BREAKING CHANGE: footer
                major bump

Write in English.
-->

## What changed

<!-- What a user of the crate or the binary gets, or loses. Not a file list. -->

## Why

<!-- The problem this solves. Link an issue if there is one. -->

## Breaking changes

<!--
Delete this section if there are none. Otherwise: what breaks, and what someone
upgrading has to do about it. The title must carry `!` and the body a
`BREAKING CHANGE:` footer.
-->

## Verification

<!-- How this was checked beyond CI: new tests, manual runs, images tried. -->
