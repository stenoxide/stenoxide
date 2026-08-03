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
5. **The prompts are an internal working device. They must never leak into committed artifacts.** See "No prompt references in code" below.

---

## Git Workflow

All work during the prompt phase happens on `main`. No branches.

**After each prompt is complete and verified, make one commit.**

Commit message format (English, conventional commits style):

    feat(prompt-N): <short description of what was implemented>

Examples:

    feat(prompt-0): scaffold workspace with stenoxide-core and stenoxide-cli
    feat(prompt-1): image_io type-state validation pipeline
    feat(prompt-3): argon2id kdf, hkdf-sha3-512 and xchacha20-poly1305 aead
    feat(prompt-2): phash margin filter with k<=1 stability hard-limit
    feat(prompt-4): jpeg artifact detection via stochastic block sampling
    feat(prompt-5): hill adaptive cost map with smooth region rejection
    feat(prompt-6): stc ffi wrapper, fisher-yates permutation and capacity sizer
    feat(prompt-7): zero-copy embed and extract pipeline with explicit ownership chain
    feat(prompt-8): integration tests and cli subcommands

**Each commit must include:**
- All source files modified in that prompt step
- The renamed `PROMPTX.done.md` file is NOT committed (it lives in the gitignored `prompts/` folder)
- `Cargo.lock` if it changed

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

**No prompt references in code:**

The `prompts/` directory is a private, gitignored scaffolding for the initial build phase. A reader of this repository has never seen it and never will, so a reference to it is noise at best and a dangling pointer at worst.

- **Never mention a prompt in any committed file.** This covers comments, doc comments, `Cargo.toml` comments, build scripts, tests, error messages, README and documentation. Forbidden forms include `PROMPT 6b`, `prompt-5`, "implemented in PROMPT 1", "since PROMPT 6b", "the measurements recorded in the prompt", and every variation of them.
- **Do not restate the prompt number when describing history.** Describing what the code *is* or *was* is fine and often useful; anchoring it to a prompt is not.
  - Wrong: `//! Implemented in PROMPT 6, replaced by a native implementation in PROMPT 6b.`
  - Right: `//! It replaces the FFI wrapper around libsdc++ this module used to carry.`
  - Wrong: `# DEPRECATED since PROMPT 6b.`
  - Right: `# DEPRECATED. The Syndrome-Trellis coder is now native Rust.`
- **"Implemented in PROMPT N" lines add nothing.** Delete them rather than rewriting them: the module doc already says what the module does, and the fact that it exists says it is implemented.
- **The only exception is commit messages.** `feat(prompt-N): ...` stays, because the prompt-phase history will be squash-merged and those subjects disappear. Nothing else gets the exception.
- The word "prompt" is perfectly fine when it means an actual prompt in the program's own domain — `PASSWORD_PROMPT`, `rpassword::prompt_password`. The rule is about the `prompts/` workflow, not the word.

---

## Architecture Reference

The system is composed of five layers. Each prompt implements one layer. Do not mix concerns across layers.

**Layer 1 — Image I/O (`image_io`):** Load, validate, and analyse the container image. The type-state pattern guarantees that no downstream code can receive an image that has not passed all validation gates.

**Layer 2 — Cryptography (`crypto`):** Key derivation (Argon2id → HKDF-SHA3-512 → DerivedKeys), authenticated encryption (XChaCha20-Poly1305), and payload compression (zstd level 19). All sensitive types implement `ZeroizeOnDrop`.

**Layer 3 — Cost Analysis (`cost`):** HILL adaptive cost map. The `CostMap<'img>` lifetime guarantees that the image buffer cannot be mutated while the cost map is alive. This invariant is enforced by the compiler, not by convention.

**Layer 4 — Embedding (`stego`):** Fisher-Yates permutation seeded by the STC key, capacity validation, and the STC encode/decode FFI wrapper. The `max_bpp` hard limit of `0.02` is a compile-time constant, not a runtime parameter.

**Layer 5 — Pipeline (`pipeline`):** Orchestrates layers 1–4 with explicit ownership transfer at each step. Every sensitive buffer is dropped and zeroed at the earliest possible point. The extraction path does not require a cost map: STC decode operates on the syndrome of all pixels, not on a stored position list.
