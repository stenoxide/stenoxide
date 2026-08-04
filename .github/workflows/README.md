# Workflows

Two workflows govern everything that leaves this repository. Work lands on
`main` through pull requests; `main` is promoted to `stable` when it has
accumulated enough to release. `stable` is the published line, and nothing
reaches crates.io without passing through a pull request into it.

## Pull request title (`pr-title.yml`)

Runs on every pull request targeting `main` or `stable`, and again whenever the
title is edited. A title that is not a Conventional Commit is **rewritten, not
rejected**: the workflow derives the right prefix from the changes the pull
request carries and edits the title in place, leaving a note in the run summary.
Its own edit fires `edited` once more, the title validates, and the check
settles green.

Repairing is only defensible because the title decides nothing. This repository
squashes with the list of replaced commits in the body (see below), and the
release job reads that list in preference to the subject — the title is
documentation. The prefix comes from the same list, so a repaired title cannot
describe the release wrongly.

Pull requests from forks are rejected rather than repaired: their token is
read-only, so there is nothing else the workflow can do.

It is a workflow of its own rather than a job inside CI because it has to react
to `edited`, and that event fires on every change to the title or the body.
Folding it into CI would retest the whole workspace each time someone reworded a
paragraph — and gating the test job on the event type instead would be worse,
since a skipped required check reads as a passing one and an edit could turn a
red run green.

### A repository setting this depends on

*Settings → General → Pull Requests → Default commit message* for squash merging
must stay at a value that includes the commit details. The API name is
`squash_merge_commit_message`, and it must be `COMMIT_MESSAGES`:

```sh
gh api repos/OWNER/REPO --jq .squash_merge_commit_message
```

Set to `PR_BODY` or `BLANK` instead, a squashed merge lands with no record of the
commits it replaced. The version would then be computed from the pull request
title alone, the changelog would shrink to one line per merge, and rewriting a
title would stop being a cosmetic act.

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
3. **Commit.** `chore: release vX.Y.Z [skip ci]`, pushed to `stable`.
4. **Build.** Three release binaries, in parallel, from that commit.
5. **GitHub Release.** Created with the three binaries attached and this
   version's changelog section as the body. **This is what creates the tag**,
   on the release commit.
6. **crates.io.** `cargo publish --workspace`, which orders the two crates by
   their dependency graph and waits for the registry to index `stenoxide-core`
   before uploading `stenoxide-cli`.

Every stage depends on the previous one. A failure anywhere stops the rest, so
a failed build never produces a half-populated release.

### Why the tag is created last

Nothing between steps 3 and 5 refers to `vX.Y.Z`; the build, the release and
the publication all check out the release commit by its sha, which the release
job hands down as an output.

Tagging in step 3, as this used to, published the version number before there
was anything to download under it. For as long as the three builds took, the
repository carried a tag whose release did not exist — and when a build failed,
it carried it permanently, with the number burnt: the next run recomputed the
same version, found the tag, and stood down as though there were nothing to
release. Creating the tag alongside the artefacts makes it mean what a reader
assumes it means, and leaves a failed run's version free to be released again
once the failure is fixed.

That retry is why the changelog step replaces any section already written for
the version being released instead of adding a second one.

## Versioning

`scripts/changes.sh` lists the Conventional Commit changes since the last tag,
oldest first, one per line, each classified as breaking, feat, fix or other and
carrying the hash and author of the commit it was read from.
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

### What a changelog entry looks like

`scripts/changelog.sh` renders the list into the section that becomes both the
`CHANGELOG.md` entry and the body of the GitHub Release:

```markdown
### Features
- **cli**: read the payload from a file — Ada Lovelace ([`0794b7d`](…/commit/0794b7d…))
- comprehensive test suite with 90% coverage requirement — Ada Lovelace ([`7738f65`](…))
```

Three things happen to a commit subject on the way in:

- **The type is dropped.** It is already the heading the entry sits under.
- **The scope is kept only when it names part of the program.** A scope
  matching `prompt`, `prompt-9`, `prompt-12` and so on is dropped: it records
  which step of the process produced the change, which means something to
  whoever ran the work and nothing to whoever is reading the release.
- **The commit is attributed and linked.** Author name, then the abbreviated
  hash linking to the commit. A line contributed by a squash carries the hash
  and author of the squash itself — the commits it replaced are not on the
  branch, so a link to one would resolve to nothing.

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
| `GITHUB_TOKEN` | `release.yml` | Pushing the release commit, and creating the tag and the GitHub Release. Provided automatically. |

`CRATES_IO_TOKEN` must be created on crates.io with publish scope for
`stenoxide-core` and `stenoxide-cli`, then added under
*Settings → Secrets and variables → Actions*. Verify with `gh secret list`.

## Branch protection

Both branches are gated by a ruleset kept in this repository, under
[`.github/rulesets/`](../rulesets/), and applied with:

```sh
gh api --method POST repos/OWNER/REPO/rulesets --input .github/rulesets/NAME.json
```

To update an existing ruleset, `PUT` to `…/rulesets/{id}` with the same file;
`gh api repos/OWNER/REPO/rulesets` lists the ids. Verify what is live with:

```sh
gh api repos/OWNER/REPO/rules/branches/NAME
```

### `stable`

`stable` publishes, so the gate in front of it is the one that has to hold: a
merge into it uploads binaries to a GitHub Release and two crates to crates.io,
neither of which can be taken back.
[`.github/rulesets/stable.json`](../rulesets/stable.json) enforces:

| Rule | Why |
|------|-----|
| Pull request required, squash only | Nothing reaches the published line without a merge that the release job can read. |
| **Test and validate** must pass | The tests, clippy, the coverage floor, `cargo audit` and the packaging dry run. |
| **Pull request title** must pass | The title is the fallback subject a squash lands with. |
| Branch must be up to date | The checks ran against what will actually be on `stable`. |
| No force push, no deletion | The tags and the published history stay where they are. |

Approvals are not required. A repository this size would only be gating on its
own author, and a rule that has to be bypassed on every merge protects nothing.
The checks are what the rule is for.

#### The one bypass

GitHub Actions is a bypass actor, and has to be. The release job pushes the
version commit to `stable` with `GITHUB_TOKEN`, and every rule above applies to
direct pushes as much as to merges — without the bypass the first release would
fail on its own protection.

This is why the rules are a ruleset rather than a classic branch protection
rule: classic protection can exempt administrators, which is both broader than
needed and does not cover a bot, while a ruleset can name GitHub Actions
specifically and leave everyone else fully gated.

### `main`

`main` collects work and publishes nothing, and everything on it is re-checked
in full by the pull request that promotes it to `stable`. What it still owes is
that nothing lands red: a pull request into `main` cannot be merged until both
checks are green. [`.github/rulesets/main.json`](../rulesets/main.json)
enforces:

| Rule | Why |
|------|-----|
| **Test and validate** must pass | The tests, clippy and the coverage floor. The release-only steps are skipped for a `main` target, so this is the correctness half of the same job. |
| **Pull request title** must pass | The title is the fallback subject a squash lands with, and what the next promotion to `stable` reads. |
| No force push, no deletion | The history a merged pull request was checked against stays where it is. |

No pull request is required, and the branch is not required to be up to date.
Both are deliberate: a direct push is still allowed (see below), and forcing a
rebase whenever something else lands first buys nothing on a branch whose
content is verified again on the way to `stable`.

#### Why an owner can still push straight to `main`

The two are not separable as cleanly as they look. A required status check is
evaluated against whatever updates the ref, so the rule that blocks a red merge
blocks a direct push too — a freshly written commit carries no checks at all,
and the push is refused outright:

```
remote: - 2 of 2 required status checks are expected.
```

No rule mode distinguishes the two cases. The API's `bypass_mode` offers
`pull_request`, which exempts an actor *on pull requests only* — precisely the
wrong way round — and `always`. So organisation owners are exempt `always`, and
the asymmetry is one of friction rather than of rule: a direct push goes
through and is recorded as a bypass, while on a pull request the merge box
shows the gate and getting past a red check takes a deliberate bypass instead
of the ordinary merge button.

For everyone else — collaborators, forks, Dependabot — the gate is absolute.

## Platforms built

| Target | Runner | Asset |
|--------|--------|-------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | `stenoxide-linux-x86_64` |
| `x86_64-pc-windows-msvc` | `windows-latest` | `stenoxide-windows-x86_64.exe` |
| `aarch64-apple-darwin` | `macos-latest` | `stenoxide-macos-arm64` |

All three are built with `cargo build --release` from the release commit — the
same commit the tag is put on once they succeed — so the binaries attached to a
GitHub Release are exactly the source that was tagged and published.
