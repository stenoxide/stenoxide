//! Raw bindings to the external libsdc++ Syndrome-Trellis Codes library.
//!
//! This is the only module in the crate where `unsafe` is permitted. Every
//! `unsafe` block added here must carry a `// SAFETY:` comment justifying why
//! it upholds the invariants of the foreign function it calls.
//!
//! Implemented in PROMPT 6.
