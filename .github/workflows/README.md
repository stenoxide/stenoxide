# Workflows

Two workflows govern everything that leaves this repository. Work lands on
`main` through pull requests; `main` is promoted to `stable` when it has
accumulated enough to release. `stable` is the published line, and nothing
reaches crates.io without passing through a pull request into it.

## CI (`ci.yml`)

Runs on every pull request targeting `main` or `stable`. It is the gate: if any
step fails, the check fails and the merge is blocked. Both branches share one
job, so both report the same status check name, but the target decides how far
it goes.

| Step | What it guarantees | `main` | `stable` |
|------|--------------------|:------:|:--------:|
| `cargo test --workspace` | The unit and integration suites pass. | yes | yes |
| `cargo clippy --workspace -- -D warnings` | No lint warning survives. | yes | yes |
| `cargo audit` | No dependency carries a known advisory. | no | yes |
| `cargo publish --workspace --dry-run` | Both crates package cleanly and would upload. | no | yes |

The last two are release concerns, not correctness ones: an advisory or a
packaging defect matters at the moment something is published, and running them
on every feature branch costs a `cargo install cargo-audit` and a full package
verification for no decision they could change. A pull request into `stable`
runs them, and that is the merge that publishes.

The publish check runs once for the whole workspace instead of once per crate.
Packaging `stenoxide-cli` alone makes cargo look up `stenoxide-core` on
crates.io, which fails whenever the version being released is not on the
registry yet — that is, on every release. `--workspace` resolves the dependency
against the sibling crate packaged in the same run.

## Release (`release.yml`)

Runs when a pull request into `stable` is *merged* (a closed-but-not-merged
pull request does nothing). It performs, in order:

1. **Version.** Computed from the commit subjects since the last tag.
2. **Changelog.** A new section is prepended to `CHANGELOG.md`.
3. **Commit and tag.** `chore: release vX.Y.Z [skip ci]`, pushed to `stable`,
   then tag `vX.Y.Z`.
4. **Build.** Three release binaries, in parallel, from the tag.
5. **GitHub Release.** Created on the tag with the three binaries attached and
   this version's changelog section as the body.
6. **crates.io.** `cargo publish --workspace`, which orders the two crates by
   their dependency graph and waits for the registry to index `stenoxide-core`
   before uploading `stenoxide-cli`.

Every stage depends on the previous one. A failure anywhere stops the rest, so
a failed build never produces a half-populated release.

## Versioning

`scripts/changes.sh` lists the Conventional Commit changes since the last tag,
oldest first, one per line, each classified as breaking, feat, fix or other.
`scripts/next-version.sh` walks that list and applies one bump per change:

| Change | Bump |
|--------|------|
| `!` before the colon, or a `BREAKING CHANGE:` footer | major |
| `feat` | minor |
| scoped `(deps)` / `(deps-dev)`, or `bump <pkg> from <a> to <b>` | none |
| everything else | patch |

Dependency bumps are listed in the changelog under *Dependencies* and move
nothing. They arrive generated and in bulk, and a resolver stepping a crate from
`0.25.1` to `0.25.2` is not a change a caller can observe. A merge carrying
nothing else leaves the version where it is, and the release job stands down —
no tag, no build, no publication — rather than failing on a tag that exists.

**Bumps accumulate.** The release is not collapsed into the single highest bump
present. From `1.2.3`, the sequence `fix, fix, fix, feat, fix, breaking, fix,
feat, fix` walks through

    1.2.4  1.2.5  1.2.6  1.3.0  1.3.1  2.0.0  2.0.1  2.1.0  2.1.1

and releases `2.1.1`. Order is what makes this different from counting each
type: the three patches at the front are absorbed by the minor that follows
them, and everything before the breaking change is absorbed by it.

With no tag in the repository the version already written in `Cargo.toml` is
used unchanged; that is how the first release picks its own number.

### Squashed merges

A squash writes the pull request title as the subject and the subjects of the
commits it replaced into the body, as a `*` list. Where that list exists it is
authoritative and the title is discarded — the title summarises the very lines
below it, and reading both would count the same work twice. Where it does not,
the title is all there is, which is why CI rejects a pull request whose title is
not a Conventional Commit.

A `BREAKING CHANGE:` footer applies to its whole commit and is emitted after
that commit's other changes, so the major bump absorbs them and one breaking
commit moves the version once.

The changelog is built from the same list that produced the version, so the two
can never disagree.

### Overriding the version by hand

The calculated version never lowers a deliberate one. If the version in the
root `Cargo.toml` is **greater** than what the commits imply, the manual value
wins and is released as written. To ship `1.0.0` out of a series of `fix:`
commits, set `version = "1.0.0"` in the root `[workspace.package]` and merge.

### Where the version lives

Three places, all of them written by the workflow:

| Location | How |
|----------|-----|
| `Cargo.toml`, `[workspace.package] version` | Rewritten by the release job. |
| `stenoxide-cli/Cargo.toml`, the `version` in the `stenoxide-core` dependency | Rewritten to the same number. |
| `Cargo.lock` | Regenerated with `cargo update --workspace`. |

Both member crates inherit the number through `version.workspace = true`, so
the root manifest is the only one to edit by hand. The dependency requirement
is the one that cannot be inherited: `path` is stripped when the crate is
packaged, and what remains is the registry requirement `^X.Y.Z`. Left at an old
number, a major release would publish `stenoxide-core 2.0.0` and then a
`stenoxide-cli` asking for `^1.0.0`, which the registry refuses.

That synchronisation runs on every release, including the ones where the
version did not change — a hand-written bump in `Cargo.toml` is precisely the
case where the dependency requirement is most likely to have been forgotten.

## Secrets

| Secret | Used by | Purpose |
|--------|---------|---------|
| `CRATES_IO_TOKEN` | `release.yml` | Publishing both crates to crates.io. |
| `GITHUB_TOKEN` | `release.yml` | Pushing the release commit, the tag and the GitHub Release. Provided automatically. |

`CRATES_IO_TOKEN` must be created on crates.io with publish scope for
`stenoxide-core` and `stenoxide-cli`, then added under
*Settings → Secrets and variables → Actions*. Verify with `gh secret list`.

## Branch protection

Both branches must be protected or the gate is decorative. Under
*Settings → Branches → Add branch protection rule*, once for `main` and once
for `stable`:

- Require a pull request before merging.
- Require status checks to pass before merging.
- Require branches to be up to date before merging.
- Required status check: **Test and validate**.

The check is named identically on both branches, so the same rule text applies;
what differs is which steps run inside it.

Do not enable "Include administrators" for pushes on `stable`: the release job
pushes the version commit and the tag back to the branch using `GITHUB_TOKEN`,
and a rule that blocks it will break every release.

## Platforms built

| Target | Runner | Asset |
|--------|--------|-------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | `stenoxide-linux-x86_64` |
| `x86_64-pc-windows-msvc` | `windows-latest` | `stenoxide-windows-x86_64.exe` |
| `aarch64-apple-darwin` | `macos-latest` | `stenoxide-macos-arm64` |

All three are built with `cargo build --release` from the release tag, so the
binaries attached to a GitHub Release are exactly the source that was tagged
and published.
