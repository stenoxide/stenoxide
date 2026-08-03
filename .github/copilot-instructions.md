# Copilot instructions

`stenoxide` hides encrypted text inside lossless images: adaptive LSB embedding
driven by HILL cost functions and Syndrome-Trellis Codes, over an Argon2id +
HKDF-SHA3-512 + XChaCha20-Poly1305 pipeline. `AGENTS.md` is the full contract
for this repository; what follows is the part that shapes generated text.

## Language

Everything committed is written in English. Source, comments, doc comments,
commit messages, pull request titles and descriptions, documentation. No
exceptions.

## Commit messages and pull request titles

Every commit subject and every pull request title is a Conventional Commit:

    <type>[(scope)][!]: <description>

The release pipeline parses these to compute the next version, so the type is a
decision, not a label:

| Type | Effect on the version |
|------|----------------------|
| `feat` | minor bump |
| `fix` | patch bump |
| `chore`, `docs`, `refactor`, `perf`, `style`, `test`, `build`, `ci`, `revert` | patch bump |
| any type with `!` before the colon, or a `BREAKING CHANGE:` footer | major bump |

Bumps accumulate: every qualifying commit in a release moves the version once,
in order. Do not invent types outside that list — an unrecognised subject is
still counted, as a patch, and the changelog entry reads as noise.

Dependency bumps are the exception: a commit scoped `(deps)` or `(deps-dev)`, or
described as `bump <package> from <a> to <b>`, is listed under *Dependencies* in
the changelog and moves nothing. Marking it `chore(deps)!:` overrides that, and
is for the bump that genuinely breaks a caller.

Scopes are the module the change lands in: `core`, `cli`, `crypto`, `stego`,
`cost`, `image-io`, `pipeline`, `deps`.

Write the description in the imperative, lowercase, with no trailing period:

    feat(cli): read the payload from a file
    fix(core): off-by-one in the capacity check
    refactor(stego)!: rework the permutation seed

Reserve `!` and `BREAKING CHANGE:` for changes that break a caller: a changed
public signature, a stego image earlier releases can no longer decode, a removed
flag. Not for internal rewrites that keep behaviour.

## Pull request descriptions

A pull request into `stable` is a release. Its description should let a reader
decide whether to upgrade, not restate the diff.

- Lead with what changed for someone using the crate or the binary.
- Call out anything breaking explicitly, and say what a user has to do about it.
- Mention new or removed flags, subcommands, features and dependencies.
- Leave out file-by-file walkthroughs and commit-by-commit narration; the
  changelog is generated from the commits already.

Never mention the `prompts/` directory or any prompt number. It is private
scaffolding that no reader of this repository has ever seen.

## Code

- No `unwrap()`, `expect()` or `panic!()` outside tests; the lint policy in
  `lib.rs` rejects them at compile time.
- Every type holding cryptographic material implements `ZeroizeOnDrop`.
- `unsafe` is confined to the FFI module and every block carries a `// SAFETY:`
  comment.
- Public and `pub(crate)` items have doc comments.
- Error messages must not distinguish a wrong password from a damaged payload
  from an image carrying nothing. That indistinguishability is a security
  property, not an oversight.
