# Changelog

## Why the numbers jump

Versions here are calculated, not chosen. The release pipeline replays every
Conventional Commit made since the previous tag and applies one bump per change,
in order, so a version records how much happened rather than only the most
significant thing that happened (see `.github/scripts/next-version.sh`). Steps
are therefore larger than a one-bump-per-release scheme would give.

Two of those steps are larger than the work behind them justifies, and the
reason is written down here rather than left to be inferred from the sections
below.

**1.7.2 → 3.7.2 — the same breaking change counted three times.** `v1.7.2` was
tagged on a squash commit, so the commits that squash replaced were not
ancestors of the tag. When `main` and `stable` were brought back into line they
arrived as new commits, and `chore(deps)!: raise the minimum supported Rust
version to 1.85` — released in 1.7.2 — was among them. The calculation met it
twice more, and a breaking change is a major bump each time it is met:
1 → 2 → 3. Nothing broke three times. The MSRV was raised once, 1.7.2 is the
release that did it, and it is still 1.85. The repeated entries in the 3.7.2
section have the same origin, which is why so many of them carry the hash of a
single merge commit (`66ee2bd`).

**3.7.2 → 3.7.4 — a release cut over an accidental revert.** #22 reverted the
CI/CD work by mistake and `v3.7.2` was tagged directly on top of it, so the
published 3.7.2 was missing roughly 2,900 lines — `generate`, the `scan`
subcommand and their tests — while its changelog announced them all. #23 put the
work back, 3.7.3 was written into `Cargo.toml` by hand to abandon the bad
number, and the pipeline added its own patch on top of that. 3.7.4 is the
result: the first release whose tree actually contains what the 3.7.2 section
describes. Generated, its section held that hand-written bump and nothing else —
the reverts and merges around it were not Conventional Commits, and what the
calculation ignores the changelog never sees — so the entries under it have been
written out by hand instead.

**If you are on 3.7.2, upgrade.** It is the only version of the two that is
incomplete — and it is the only tag with no release behind it, since the build
that would have published it never finished.

From 3.7.4 onwards the numbers come from a history with nothing counted twice.
They still move in large steps — 3.7.4 to 3.16.4 is nine features, with four
smaller changes landing after the last of them — but every step in them is a
change that was made once.

## [3.7.4] - 2026-08-04

_First installable release since 1.7.2, and the one that ships the work below.
The entries are written by hand: generated, this section held the version bump
alone, because the reverts and merges that make up the rest were not
Conventional Commits and the calculation never saw them. Everything the 3.7.2
section lists that is not repeated here had already shipped in 1.7.2 — see "Why
the numbers jump" above._

### Features
- **core**: generate a container around the payload (#14) — [@adrian-cancio](https://github.com/adrian-cancio) ([`ee99089`](https://github.com/stenoxide/stenoxide/commit/ee99089300fd301db1d17dee31f870048b6d17bf))
- **generate**: let the container size be chosen when a payload overflows (#16, re-applied as #19 after the revert) — [@adrian-cancio](https://github.com/adrian-cancio) ([`3cac4f6`](https://github.com/stenoxide/stenoxide/commit/3cac4f6684263cd5574d9721b0fc2d1552eb856b))

### Bug Fixes
- **cli**: guide instead of failing when extracting binary to a terminal (#15) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66c6693`](https://github.com/stenoxide/stenoxide/commit/66c6693cca73f929846953a93f81af191a45c163))
- resolve the merge conflicts blocking #17 (`main` → `stable`) (#20) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))

### Other Changes
- restore the CI/CD work that #22 reverted by mistake (#23) — [@adrian-cancio](https://github.com/adrian-cancio) ([`9819110`](https://github.com/stenoxide/stenoxide/commit/9819110fc62d57facbfeeb53900b8791fd6e2078))
- bump version to 3.7.3 by hand, to leave the bad number behind (#24) — [@adrian-cancio](https://github.com/adrian-cancio) ([`1f748bf`](https://github.com/stenoxide/stenoxide/commit/1f748bf77494c09e73f881ea73ec8357b31d2cd1))

## [3.7.2] - 2026-08-04

_Withdrawn: this tag sits on top of an accidental revert and its binaries are
missing the work listed below. Use 3.7.4, which ships it. The two major bumps
between 1.7.2 and this version, and the entries repeated from 1.7.2, both come
from merge commits that re-listed history already released — see "Why the
numbers jump" above._

### Breaking Changes
- **deps**: raise the minimum supported Rust version to 1.85 — [@adrian-cancio](https://github.com/adrian-cancio) ([`c62c593`](https://github.com/stenoxide/stenoxide/commit/c62c59303915cd867b20d36a5dc4f212ea2ea927))
- **deps**: raise the minimum supported Rust version to 1.85 — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))

### Features
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`c176594`](https://github.com/stenoxide/stenoxide/commit/c176594e6d2cc8e499f8c693b470b94e14e8b598))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`07c0383`](https://github.com/stenoxide/stenoxide/commit/07c0383bd2c0f2e39fdc340a3e2dc6fc71f013ea))
- comprehensive test suite with 90% coverage requirement — [@adrian-cancio](https://github.com/adrian-cancio) ([`7738f65`](https://github.com/stenoxide/stenoxide/commit/7738f651a1b9ce8c571aec8dcf308184e1c83a9f))
- **cli**: scan subcommand, pre-auth container validation and actionable errors — [@adrian-cancio](https://github.com/adrian-cancio) ([`e97366d`](https://github.com/stenoxide/stenoxide/commit/e97366d4fa6b7271e7bbaad169e771059e462980))
- **cli**: progress reporting, and a size ceiling that stops the scan hanging — [@adrian-cancio](https://github.com/adrian-cancio) ([`0794b7d`](https://github.com/stenoxide/stenoxide/commit/0794b7d0f6c96424a311b90fe11618d23c28c6c5))
- **cli**: end a typed message with a dot, and say so (#4) — [@adrian-cancio](https://github.com/adrian-cancio) ([`d8674a3`](https://github.com/stenoxide/stenoxide/commit/d8674a3c22a57285e35c90313a6e5d529d1c4aa2))
- **cli**: read the payload from a file and write it back to one — [@adrian-cancio](https://github.com/adrian-cancio) ([`37510ba`](https://github.com/stenoxide/stenoxide/commit/37510bafb9b87703b318388e571ede52d7a735ea))
- Add the release pipeline (#1) — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- **core**: generate a container around the payload (#14) — [@adrian-cancio](https://github.com/adrian-cancio) ([`ee99089`](https://github.com/stenoxide/stenoxide/commit/ee99089300fd301db1d17dee31f870048b6d17bf))
- **generate**: let the container size be chosen when a payload overflows (#16) — [@adrian-cancio](https://github.com/adrian-cancio) ([`3cac4f6`](https://github.com/stenoxide/stenoxide/commit/3cac4f6684263cd5574d9721b0fc2d1552eb856b))
- **generate**: let the container size be chosen when a payload overflows (#19) — [@adrian-cancio](https://github.com/adrian-cancio) ([`d14b912`](https://github.com/stenoxide/stenoxide/commit/d14b9124c32de560007ae56969a2b7fd5d89f244))
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- comprehensive test suite with 90% coverage requirement — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **cli**: scan subcommand, pre-auth container validation and actionable errors — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **cli**: progress reporting, and a size ceiling that stops the scan hanging — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **cli**: end a typed message with a dot, and say so (#4) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **cli**: read the payload from a file and write it back to one (#9) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **cli**: read the payload from a file and write it back to one — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- Add the release pipeline (#1) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))

### Bug Fixes
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`ebd976a`](https://github.com/stenoxide/stenoxide/commit/ebd976a9c8100b2bc5da4c67a70e38265561ac50))
- **ci**: statistically valid steganalysis with proportional payload and crops — [@adrian-cancio](https://github.com/adrian-cancio) ([`dca6d4a`](https://github.com/stenoxide/stenoxide/commit/dca6d4a300c21c91435cbc468123619ddd994f32))
- **research**: stop the analysis assuming one particular texture — [@adrian-cancio](https://github.com/adrian-cancio) ([`5db7f50`](https://github.com/stenoxide/stenoxide/commit/5db7f50fe335f888a39e43d710597783a4882100))
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- **cli**: guide instead of failing when extracting binary to a terminal (#15) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66c6693`](https://github.com/stenoxide/stenoxide/commit/66c6693cca73f929846953a93f81af191a45c163))
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **ci**: statistically valid steganalysis with proportional payload and crops — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **research**: stop the analysis assuming one particular texture — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))

### Other Changes
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`0fc4c46`](https://github.com/stenoxide/stenoxide/commit/0fc4c46352900f836396e2aa4e05593dcbdcf127))
- operational security guide — [@adrian-cancio](https://github.com/adrian-cancio) ([`e436553`](https://github.com/stenoxide/stenoxide/commit/e4365531408c56b445a1309c4e0c80a4939caca9))
- explain why the container restrictions exist — [@adrian-cancio](https://github.com/adrian-cancio) ([`de86fb3`](https://github.com/stenoxide/stenoxide/commit/de86fb39415d8a0ef7d3e00052879515ea6ddabc))
- install llvm-tools-preview for the coverage gate — [@adrian-cancio](https://github.com/adrian-cancio) ([`cad8e4d`](https://github.com/stenoxide/stenoxide/commit/cad8e4dfcf3b05287db5011be969b3973f014ee2))
- **cli**: say why embedding gets a spinner rather than a bar — [@adrian-cancio](https://github.com/adrian-cancio) ([`d0d5a68`](https://github.com/stenoxide/stenoxide/commit/d0d5a6857d67f8d58e7644af6f00892edb7af9aa))
- **release**: tag with the artefacts, and attribute every changelog line (#2) — [@adrian-cancio](https://github.com/adrian-cancio) ([`aa94698`](https://github.com/stenoxide/stenoxide/commit/aa94698f37d5addd91f8cd69861cf5c2bcfbc0d8))
- **release**: let a changelog section be re-rendered at its original date (#5) — [@adrian-cancio](https://github.com/adrian-cancio) ([`7f801dd`](https://github.com/stenoxide/stenoxide/commit/7f801dd9fa12d69c804146e755a2917c320ccc1e))
- ruleset probe — [@adrian-cancio](https://github.com/adrian-cancio) ([`80f7aa4`](https://github.com/stenoxide/stenoxide/commit/80f7aa48a38152acb6ffe85c064e79838aac3461))
- **rulesets**: gate merges into main on the checks it already runs — [@adrian-cancio](https://github.com/adrian-cancio) ([`80f7aa4`](https://github.com/stenoxide/stenoxide/commit/80f7aa48a38152acb6ffe85c064e79838aac3461))
- **release**: let a changelog section be re-rendered at its original date — [@adrian-cancio](https://github.com/adrian-cancio) ([`0e27b21`](https://github.com/stenoxide/stenoxide/commit/0e27b21a10ab7886f8def675ecc1c3b831b69eed))
- **release**: credit the GitHub account, not the name in the commit — [@adrian-cancio](https://github.com/adrian-cancio) ([`0e27b21`](https://github.com/stenoxide/stenoxide/commit/0e27b21a10ab7886f8def675ecc1c3b831b69eed))
- apply the current rustfmt to the files it had drifted from — [@adrian-cancio](https://github.com/adrian-cancio) ([`37510ba`](https://github.com/stenoxide/stenoxide/commit/37510bafb9b87703b318388e571ede52d7a735ea))
- keep prompt references out of the git history too (#10) — [@adrian-cancio](https://github.com/adrian-cancio) ([`b413cba`](https://github.com/stenoxide/stenoxide/commit/b413cba58cb770d5a52b1511360afe860b4a1b6c))
- **actions**: run the tests and the coverage floor only into stable (#11) — [@adrian-cancio](https://github.com/adrian-cancio) ([`9e4c4ba`](https://github.com/stenoxide/stenoxide/commit/9e4c4ba20a14d380c781bd4fe46fa925a4ad41b2))
- record the interface decision, and what is still unanswered — [@adrian-cancio](https://github.com/adrian-cancio) ([`5db7f50`](https://github.com/stenoxide/stenoxide/commit/5db7f50fe335f888a39e43d710597783a4882100))
- keep the write-up in step with what was measured — [@adrian-cancio](https://github.com/adrian-cancio) ([`5db7f50`](https://github.com/stenoxide/stenoxide/commit/5db7f50fe335f888a39e43d710597783a4882100))
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- re-render the 0.1.0 changelog entry in the current format — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- credit the 0.1.0 entries by GitHub handle — [@adrian-cancio](https://github.com/adrian-cancio) ([`98d5908`](https://github.com/stenoxide/stenoxide/commit/98d590861004f67a27574cbca525445b46fa4ec0))
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- operational security guide — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- explain why the container restrictions exist — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- install llvm-tools-preview for the coverage gate — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **cli**: say why embedding gets a spinner rather than a bar — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **release**: tag with the artefacts, and attribute every changelog line (#2) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **release**: let a changelog section be re-rendered at its original date (#5) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **rulesets**: gate merges into main on the checks it already runs (#7) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- ruleset probe — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **rulesets**: gate merges into main on the checks it already runs — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **release**: credit changelog entries by GitHub handle (#8) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **release**: let a changelog section be re-rendered at its original date — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **release**: credit the GitHub account, not the name in the commit — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- apply the current rustfmt to the files it had drifted from — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- keep prompt references out of the git history too (#10) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **actions**: run the tests and the coverage floor only into stable (#11) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- **research**: whether a generated container can be made undetectable (#6) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- record the interface decision, and what is still unanswered — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- keep the write-up in step with what was measured — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- merge the stable release history back into main (#13) — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- re-render the 0.1.0 changelog entry in the current format — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))
- credit the 0.1.0 entries by GitHub handle — [@adrian-cancio](https://github.com/adrian-cancio) ([`66ee2bd`](https://github.com/stenoxide/stenoxide/commit/66ee2bdbe9777a92e60cf11143e98da890e3d51d))

## [1.7.2] - 2026-08-04

_First release made by the calculated-version pipeline. The step from 0.1.0 is
the pipeline replaying every change accumulated since it — one MSRV break, seven
features and two fixes — rather than a single bump._

### Breaking Changes
- **deps**: raise the minimum supported Rust version to 1.85 — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))

### Features
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- comprehensive test suite with 90% coverage requirement — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **cli**: scan subcommand, pre-auth container validation and actionable errors — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **cli**: progress reporting, and a size ceiling that stops the scan hanging — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **cli**: end a typed message with a dot, and say so (#4) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **cli**: read the payload from a file and write it back to one (#9) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **cli**: read the payload from a file and write it back to one — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- Add the release pipeline (#1) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))

### Bug Fixes
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **ci**: statistically valid steganalysis with proportional payload and crops — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **research**: stop the analysis assuming one particular texture — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))

### Other Changes
- re-render the 0.1.0 changelog entry in the current format — [@adrian-cancio](https://github.com/adrian-cancio) ([`0d5f368`](https://github.com/stenoxide/stenoxide/commit/0d5f3686699fccb9aadf785d96c46a7685967364))
- credit the 0.1.0 entries by GitHub handle — [@adrian-cancio](https://github.com/adrian-cancio) ([`b90dfa5`](https://github.com/stenoxide/stenoxide/commit/b90dfa593b75445461a245e9f5631e27e92ed6e4))
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- operational security guide — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- explain why the container restrictions exist — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- install llvm-tools-preview for the coverage gate — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **cli**: say why embedding gets a spinner rather than a bar — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **release**: tag with the artefacts, and attribute every changelog line (#2) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **release**: let a changelog section be re-rendered at its original date (#5) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **rulesets**: gate merges into main on the checks it already runs (#7) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- ruleset probe — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **rulesets**: gate merges into main on the checks it already runs — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **release**: credit changelog entries by GitHub handle (#8) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **release**: let a changelog section be re-rendered at its original date — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **release**: credit the GitHub account, not the name in the commit — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- apply the current rustfmt to the files it had drifted from — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- keep prompt references out of the git history too (#10) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **actions**: run the tests and the coverage floor only into stable (#11) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- **research**: whether a generated container can be made undetectable (#6) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- record the interface decision, and what is still unanswered — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- keep the write-up in step with what was measured — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- merge the stable release history back into main (#13) — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- re-render the 0.1.0 changelog entry in the current format — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))
- credit the 0.1.0 entries by GitHub handle — [@adrian-cancio](https://github.com/adrian-cancio) ([`11855a9`](https://github.com/stenoxide/stenoxide/commit/11855a9d81ff71740879c88702848522457979b0))

## [0.1.0] - 2026-08-03

### Features
- scaffold workspace with stenoxide-core and stenoxide-cli — [@adrian-cancio](https://github.com/adrian-cancio) ([`930ee5f`](https://github.com/stenoxide/stenoxide/commit/930ee5fdc93b824500f3a67b2ddbc40750e7a66f))
- image_io type-state validation pipeline — [@adrian-cancio](https://github.com/adrian-cancio) ([`c0e7114`](https://github.com/stenoxide/stenoxide/commit/c0e711402d506d9aaea9ca37415144c6af7c68f4))
- argon2id kdf, hkdf-sha3-512 and xchacha20-poly1305 aead — [@adrian-cancio](https://github.com/adrian-cancio) ([`4ed29eb`](https://github.com/stenoxide/stenoxide/commit/4ed29ebb3cd0d1e26c837eb0101ace5fdf64a8f0))
- phash margin filter with k<=1 stability hard-limit — [@adrian-cancio](https://github.com/adrian-cancio) ([`c006b51`](https://github.com/stenoxide/stenoxide/commit/c006b51c2f2516b2a29780d660d76d4cf73a5677))
- jpeg artifact detection via stochastic block sampling — [@adrian-cancio](https://github.com/adrian-cancio) ([`433a58f`](https://github.com/stenoxide/stenoxide/commit/433a58f74ff008e616efae3dd4085056c775d58d))
- hill adaptive cost map with smooth region rejection — [@adrian-cancio](https://github.com/adrian-cancio) ([`4c86b15`](https://github.com/stenoxide/stenoxide/commit/4c86b15d5f06361428ef28482593e1025da05d7b))
- stc ffi wrapper, fisher-yates permutation and capacity sizer — [@adrian-cancio](https://github.com/adrian-cancio) ([`1c714da`](https://github.com/stenoxide/stenoxide/commit/1c714da2c9ff15ec322cefd8b99c4a967b7b1b63))
- zero-copy embed and extract pipeline with explicit ownership chain — [@adrian-cancio](https://github.com/adrian-cancio) ([`08606b6`](https://github.com/stenoxide/stenoxide/commit/08606b6291e3070bc43a20a7b20901a4b2a5b43c))
- integration tests and cli subcommands — [@adrian-cancio](https://github.com/adrian-cancio) ([`af62e47`](https://github.com/stenoxide/stenoxide/commit/af62e4794f39ca97ec17bf5eed48055191acd493))
- native rust STC implementation replacing FFI dependency — [@adrian-cancio](https://github.com/adrian-cancio) ([`68e60ff`](https://github.com/stenoxide/stenoxide/commit/68e60ffe505e1fdfba7971871b4a1c1b055f9908))
- steganalysis validation script using aletheia — [@adrian-cancio](https://github.com/adrian-cancio) ([`83088ce`](https://github.com/stenoxide/stenoxide/commit/83088ce7d69fbc19107653358d5cf70ec094f8f9))
- CI/CD with automated versioning, multiplataform builds and crates.io publishing — [@adrian-cancio](https://github.com/adrian-cancio) ([`6c6d9a3`](https://github.com/stenoxide/stenoxide/commit/6c6d9a31bb77a1b137d6688882a71e3ba7c460b2))
- **ci**: rewrite a non-conforming pull request title instead of rejecting it — [@adrian-cancio](https://github.com/adrian-cancio) ([`6c6d9a3`](https://github.com/stenoxide/stenoxide/commit/6c6d9a31bb77a1b137d6688882a71e3ba7c460b2))

### Bug Fixes
- **ci**: re-check the pull request title when it is edited — [@adrian-cancio](https://github.com/adrian-cancio) ([`6c6d9a3`](https://github.com/stenoxide/stenoxide/commit/6c6d9a31bb77a1b137d6688882a71e3ba7c460b2))

### Other Changes
- resolve rustdoc intra-doc link warnings — [@adrian-cancio](https://github.com/adrian-cancio) ([`c72c183`](https://github.com/stenoxide/stenoxide/commit/c72c18304a6e2a9b1d9ab8c8c74e27ded73cb117))
- drop prompt references from committed artifacts — [@adrian-cancio](https://github.com/adrian-cancio) ([`693b3f4`](https://github.com/stenoxide/stenoxide/commit/693b3f4036003e8311011eb80b4f4506ca8a2a75))
- prepare crates.io release metadata and documentation — [@adrian-cancio](https://github.com/adrian-cancio) ([`75491fe`](https://github.com/stenoxide/stenoxide/commit/75491fe8dc646b0f4ca297efa76cb604675c75c2))
- iterative conventional-commit versioning and pull request conventions — [@adrian-cancio](https://github.com/adrian-cancio) ([`6c6d9a3`](https://github.com/stenoxide/stenoxide/commit/6c6d9a31bb77a1b137d6688882a71e3ba7c460b2))

### Dependencies
- **deps**: bring every dependency to its latest release — [@adrian-cancio](https://github.com/adrian-cancio) ([`feda9dc`](https://github.com/stenoxide/stenoxide/commit/feda9dc9d4ffc4fc2a6bdc3c222563adf0020a7b))

