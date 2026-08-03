# Changelog

## [0.1.0] - 2026-08-03

### Features
- feat(prompt-0): scaffold workspace with stenoxide-core and stenoxide-cli
- feat(prompt-1): image_io type-state validation pipeline
- feat(prompt-3): argon2id kdf, hkdf-sha3-512 and xchacha20-poly1305 aead
- feat(prompt-2): phash margin filter with k<=1 stability hard-limit
- feat(prompt-4): jpeg artifact detection via stochastic block sampling
- feat(prompt-5): hill adaptive cost map with smooth region rejection
- feat(prompt-6): stc ffi wrapper, fisher-yates permutation and capacity sizer
- feat(prompt-7): zero-copy embed and extract pipeline with explicit ownership chain
- feat(prompt-8): integration tests and cli subcommands
- feat(prompt-6b): native rust STC implementation replacing FFI dependency
- feat(prompt-9): steganalysis validation script using aletheia
- feat(prompt-11): CI/CD with automated versioning, multiplataform builds and crates.io publishing
- feat(ci): rewrite a non-conforming pull request title instead of rejecting it

### Bug Fixes
- fix(ci): re-check the pull request title when it is edited

### Other Changes
- docs: resolve rustdoc intra-doc link warnings
- docs: drop prompt references from committed artifacts
- chore(prompt-10): prepare crates.io release metadata and documentation
- ci: iterative conventional-commit versioning and pull request conventions

### Dependencies
- build(deps): bring every dependency to its latest release

