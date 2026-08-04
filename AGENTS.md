# AGENTS.md — stenoxide

## Project Overview

`stenoxide` is a steganography system that hides encrypted text payloads inside lossless images using adaptive LSB embedding with HILL cost functions and Syndrome-Trellis Codes (STC). The cryptographic pipeline is built around Argon2id + HKDF-SHA3-512 + XChaCha20-Poly1305, designed to resist both classical and post-quantum adversaries.

This file is the source of truth for how this repository is maintained. Read it before writing a single line of code or making any commit.

---

## Language Policy

This is a strict, non-negotiable rule that applies to every decision you make:

- **All committed artifacts must be written in 100% English.** This includes: source code, comments, doc comments, commit messages, error messages in code, variable names, README, and any other file tracked by git.
- **Respond to the user in whatever language they write to you.** If they write in Spanish, reply in Spanish. If they switch to English, switch to English. Never force a language on the user.
- **The `prompts/` directory is excluded from git** (see `.gitignore`). Files inside it are working instructions, not project artifacts. Their language does not matter and they are never committed.

If you are unsure whether a file will be committed: assume it will be, and write it in English.

---

## Repository Structure

    stenoxide/
    ├── AGENTS.md
    ├── .gitignore
    ├── Cargo.toml
    ├── Cargo.lock
    ├── prompts/
    │   ├── PROMPT0.md
    │   ├── PROMPT1.md
    │   ├── PROMPT1.done.md
    │   └── ...
    ├── stenoxide-core/
    │   ├── Cargo.toml
    │   ├── build.rs
    │   └── src/
    │       ├── lib.rs
    │       ├── image_io/
    │       ├── cost/
    │       ├── crypto/
    │       ├── stego/
    │       └── pipeline/
    └── stenoxide-cli/
        ├── Cargo.toml
        └── src/
            └── main.rs

---

## Gitignore

The `.gitignore` must contain at minimum:

    /target
    prompts/
    *.env
    LIBSDC_PATH

`Cargo.lock` is intentionally NOT ignored. This workspace contains a binary crate (`stenoxide-cli`). Locking dependencies is correct and required.

---

## Prompt Workflow

All development during the initial build phase is driven by numbered prompt files inside the `prompts/` directory. Each file is a self-contained specification for one module or layer of the system.

**Execution order and verification commands:**

| Step | File | Verification command |
|------|------|----------------------|
| 0 | PROMPT0.md | `cargo check --workspace` |
| 1 | PROMPT1.md | `cargo check -p stenoxide-core` |
| 2 | PROMPT3.md | `cargo check -p stenoxide-core` |
| 3 | PROMPT2.md | `cargo check -p stenoxide-core` |
| 4 | PROMPT4.md | `cargo check -p stenoxide-core` |
| 5 | PROMPT5.md | `cargo check -p stenoxide-core` |
| 6 | PROMPT6.md | `cargo check -p stenoxide-core` |
| 7 | PROMPT7.md | `cargo check --workspace` |
| 8 | PROMPT8.md | `cargo test --workspace && cargo clippy --workspace -- -D warnings` |

**Rules:**

1. Execute one prompt at a time. Never start the next prompt while the verification command of the current one returns errors.
2. Warnings are acceptable during intermediate steps. Errors are not.
3. When a prompt is complete and its verification passes, rename the file: `PROMPTX.md` → `PROMPTX.done.md`. This signals that the step is closed and must not be revisited unless explicitly instructed.
4. Never modify a `.done.md` file unless the user explicitly asks you to reopen that step.
5. **The prompts are an internal working device. They must never leak into committed artifacts, and that includes commit messages.** See "No prompt references in committed artifacts" below.

---

## Git Workflow

All work during the prompt phase happens on `main`. No branches.

**After each prompt is complete and verified, make one commit.**

Commit message format (English, conventional commits style — the same shape as
every other commit in this repository, described under "Commit Conventions"
below):

    <type>(<scope>): <short description of what was implemented>

**The scope is the module the work landed in, never the prompt number.** A
commit subject is read by the release pipeline and by anyone browsing the
history; neither has ever seen `prompts/`. Describe the change, not the step
that produced it.

Examples:

    build: scaffold the workspace with stenoxide-core and stenoxide-cli
    feat(image-io): type-state validation pipeline
    feat(crypto): argon2id kdf, hkdf-sha3-512 and xchacha20-poly1305 aead
    feat(image-io): phash margin filter with k<=1 stability hard-limit
    feat(image-io): jpeg artifact detection via stochastic block sampling
    feat(cost): hill adaptive cost map with smooth region rejection
    feat(stego): stc coder, fisher-yates permutation and capacity sizer
    feat(pipeline): zero-copy embed and extract with explicit ownership chain
    feat(cli): embed and extract subcommands

Wrong, in every form: `feat(prompt-6): ...`, `feat(stego): implement PROMPT 6b`,
`fix(cost): as specified in the prompt`, and a body or footer that names one.

**Each commit must include:**
- All source files modified in that prompt step
- The renamed `PROMPTX.done.md` file is NOT committed (it lives in the gitignored `prompts/` folder)
- `Cargo.lock` if it changed

---

## Commit Conventions

Once the prompt phase closes, work lands on `main` through pull requests and
`main` is promoted to `stable` when it has accumulated enough to release. The
release pipeline reads the commits to decide the version, so **a commit subject
is an instruction to that pipeline, not a label**. Getting the type wrong
publishes the wrong version number.

Every commit subject and every pull request title has this shape:

    <type>[(scope)][!]: <description>

### Types, and what each one does to the version

| Type | Meaning | Bump |
|------|---------|------|
| `feat` | New capability a user can reach | minor |
| `fix` | Corrected behaviour | patch |
| `perf` | Faster or leaner, same behaviour | patch |
| `refactor` | Internal restructuring, same behaviour | patch |
| `docs` | Documentation only | patch |
| `test` | Tests only | patch |
| `build` | Build system, manifests, packaging | patch |
| `ci` | Workflows and release tooling | patch |
| `chore` | Dependencies, housekeeping | patch |
| `style` | Formatting only | patch |
| `revert` | Undoes an earlier commit | patch |

Nothing outside this list. An unrecognised type is not rejected by the release
job — it is silently counted as a patch and lands in the changelog as noise.

### Dependency bumps do not move the version

A commit scoped `(deps)` or `(deps-dev)`, or whose description reads
`bump <package> from <a> to <b>`, is recorded in the changelog under
*Dependencies* and contributes no bump at all. These arrive generated and in
bulk, and a resolver moving a transitive crate from `0.25.1` to `0.25.2` is not
something a caller can observe. A merge carrying nothing else leaves the version
where it was and publishes nothing.

When a bump *does* break something — a raised MSRV, a dependency whose API leaks
through ours — mark it `chore(deps)!:` and it becomes a major like any other.

### Breaking changes

A `!` before the colon, or a `BREAKING CHANGE:` footer in the body, bumps the
major version:

    refactor(stego)!: rework the permutation seed

    BREAKING CHANGE: images embedded by earlier releases cannot be decoded.

Reserve it for what actually breaks a caller: a changed public signature, a
removed flag, a stego image an earlier release can no longer read. Not for
internal rewrites that preserve behaviour. A stray `!` publishes a major version
and there is no taking it back off crates.io.

### Bumps accumulate

Every qualifying commit in a release moves the version once, in order — the
release is not collapsed into a single highest bump. From `1.2.3`, a series of
`fix, fix, fix, feat, fix, feat, fix` lands on `1.4.1`, not on `1.3.0`:

    1.2.4  1.2.5  1.2.6  1.3.0  1.3.1  1.4.0  1.4.1

Order matters, which is why this is not a count of each type: the three patches
at the front are absorbed by the minor that follows them, the one after it
survives.

### Scopes

The module the change lands in: `core`, `cli`, `crypto`, `stego`, `cost`,
`image-io`, `pipeline`, `deps`. Optional, but use it when the change is confined
to one of them.

### Descriptions

Imperative, lowercase, no trailing period, English:

    feat(cli): read the payload from a file
    fix(core): off-by-one in the capacity check
    chore(deps): bring image to 0.25

### Pull request titles

Squash merging is the norm, and a squash writes the pull request title as the
subject of the commit that lands on the branch. When the squash body carries the
list of replaced commits, that list is what the release job reads and the title
is discarded; when it does not, the title is the only thing there is. Either
way it must be a Conventional Commit, and CI rejects it if it is not.

---

## Code Standards

These rules apply to every file you write or modify:

**Rust:**
- No `unwrap()`, no `expect()`, no `panic!()` outside of tests. The linting policy in `lib.rs` enforces this at compile time.
- All types containing cryptographic material must implement `ZeroizeOnDrop`. No exceptions.
- `unsafe` is permitted exclusively in `stenoxide-core/src/stego/stc/ffi.rs`. Every `unsafe` block in that file must have a `// SAFETY:` comment explaining why it is sound.
- Doc comments on all public and `pub(crate)` items. English only.
- Lifetimes must be named descriptively when they carry semantic meaning (e.g. `'img` for borrows tied to an `ImageBuffer`).

**General:**
- No secrets, credentials, or keys in any committed file.
- No `TODO` or `FIXME` comments left in committed code without an accompanying explanation of what is blocking the fix.

**No prompt references in committed artifacts:**

The `prompts/` directory is a private, gitignored scaffolding for the initial build phase. A reader of this repository has never seen it and never will, so a reference to it is noise at best and a dangling pointer at worst.

- **Never mention a prompt in any committed file.** This covers comments, doc comments, `Cargo.toml` comments, build scripts, tests, error messages, README and documentation. Forbidden forms include `PROMPT 6b`, `prompt-5`, "implemented in PROMPT 1", "since PROMPT 6b", "the measurements recorded in the prompt", and every variation of them.
- **Never mention a prompt in the git history either.** Commit subjects, commit bodies, footers, branch names, pull request titles and pull request descriptions are committed artifacts too — they outlive the working files and are the first thing a stranger reads. `feat(prompt-4): ...` and "closes PROMPT 4" are as forbidden as a comment saying the same thing.
- **Do not restate the prompt number when describing history.** Describing what the code *is* or *was* is fine and often useful; anchoring it to a prompt is not.
  - Wrong: `//! Implemented in PROMPT 6, replaced by a native implementation in PROMPT 6b.`
  - Right: `//! It replaces the FFI wrapper around libsdc++ this module used to carry.`
  - Wrong: `# DEPRECATED since PROMPT 6b.`
  - Right: `# DEPRECATED. The Syndrome-Trellis coder is now native Rust.`
- **"Implemented in PROMPT N" lines add nothing.** Delete them rather than rewriting them: the module doc already says what the module does, and the fact that it exists says it is implemented.
- **There is no exception.** The rule used to spare commit subjects on the grounds that the prompt-phase history would be squashed away; it no longer does. Nothing committed names a prompt.
- The word "prompt" is perfectly fine when it means an actual prompt in the program's own domain — `PASSWORD_PROMPT`, `rpassword::prompt_password`. The rule is about the `prompts/` workflow, not the word.

---

## README Maintenance

The root `README.md` and `stenoxide-core/README.md` describe what the system
*is* and how it behaves today. They are not a changelog and not a place to
record work. Keep them true; otherwise leave them alone.

**Update the README when, and only when, a change makes it wrong or incomplete
for a reader who has never seen the code:**

- Something it states is no longer true — an algorithm it names was replaced, a
  parameter it quotes changed, a requirement was relaxed or tightened.
- Something a user needs in order to use the project appeared or disappeared — a
  subcommand, a flag, an installation step, a new crate, a supported format.
- A claim in "Security model" stopped holding, or a new one has to be made.

**Do not touch the README for:**

- Internal refactors, renames of private items, module reorganisations.
- Bug fixes, new tests, performance work, dependency bumps.
- Anything the README does not already mention and that a user does not need to
  know about.

**How to edit it when an edit is warranted:**

- Change the sentence that is now wrong, inside the section that already covers
  the topic. Replace text; do not accumulate it next to what is already there.
- Never add a "Changelog", "Recent changes", "What's new" or "Notes" section, and
  never append a line per commit. The structure of the document is fixed; growth
  is a defect, not a sign of maintenance.
- If a change genuinely needs a section that does not exist, say so and add one
  deliberately — that is a rare event, not a routine one.

The test before editing: *does the README now say something false, or omit
something a first-time user needs?* If the answer is no, the README is finished
for that change.

---

## Architecture Reference

The system is composed of five layers. Each prompt implements one layer. Do not mix concerns across layers.

**Layer 1 — Image I/O (`image_io`):** Load, validate, and analyse the container image. The type-state pattern guarantees that no downstream code can receive an image that has not passed all validation gates.

**Layer 2 — Cryptography (`crypto`):** Key derivation (Argon2id → HKDF-SHA3-512 → DerivedKeys), authenticated encryption (XChaCha20-Poly1305), and payload compression (zstd level 19). All sensitive types implement `ZeroizeOnDrop`.

**Layer 3 — Cost Analysis (`cost`):** HILL adaptive cost map. The `CostMap<'img>` lifetime guarantees that the image buffer cannot be mutated while the cost map is alive. This invariant is enforced by the compiler, not by convention.

**Layer 4 — Embedding (`stego`):** Fisher-Yates permutation seeded by the STC key, capacity validation, and the STC encode/decode FFI wrapper. The `max_bpp` hard limit of `0.02` is a compile-time constant, not a runtime parameter.

**Layer 5 — Pipeline (`pipeline`):** Orchestrates layers 1–4 with explicit ownership transfer at each step. Every sensitive buffer is dropped and zeroed at the earliest possible point. The extraction path does not require a cost map: STC decode operates on the syndrome of all pixels, not on a stored position list.
