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

Versions follow Conventional Commits. Each commit subject between the last tag
and `HEAD` is classified, and the highest classification present decides the
bump:

| Commit subject | Bump |
|----------------|------|
| `BREAKING CHANGE`, `feat!:`, `fix!:` | major |
| `feat:` | minor |
| `fix:`, `chore:`, `docs:`, `refactor:`, `perf:` | patch |

With no tag in the repository the version already written in `Cargo.toml` is
used unchanged; that is how the first release picks its own number.

### Overriding the version by hand

The calculated version never lowers a deliberate one. If the version in the
root `Cargo.toml` is **greater** than what the commits imply, the manual value
wins and is released as written. To ship `1.0.0` out of a series of `fix:`
commits, set `version = "1.0.0"` in the root `[workspace.package]` and merge.

Both member crates inherit that number through `version.workspace = true`, so
the root manifest is the only place to edit. The workflow additionally rewrites
the registry requirement `stenoxide-cli` states on `stenoxide-core`, which has
to track the version or a major bump would leave the CLI depending on a range
the newly published core does not satisfy.

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
