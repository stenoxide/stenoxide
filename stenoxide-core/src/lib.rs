//! # stenoxide-core
//!
//! Core engine of the `stenoxide` steganography system.
//!
//! The crate is organised as five layers that are composed, never mixed:
//!
//! 1. [`image_io`] — loading, validation and analysis of the container image.
//! 2. [`crypto`] — key derivation, authenticated encryption and compression.
//! 3. [`cost`] — HILL adaptive cost map over the validated image.
//! 4. [`stego`] — permutation, capacity sizing and Syndrome-Trellis Codes.
//! 5. [`pipeline`] — orchestration of the layers above with explicit ownership
//!    transfer, so that sensitive buffers are dropped and zeroed as early as
//!    possible.
//!
//! ## Linting policy
//!
//! Fallible operations must be expressed through `Result`. Panicking helpers
//! and `unsafe` are denied crate-wide; the single documented exception is the
//! STC FFI wrapper, which re-enables `unsafe` locally and justifies every block
//! with a `// SAFETY:` comment.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(missing_docs)]

pub mod cost;
pub mod crypto;
pub mod image_io;
pub mod pipeline;
pub mod stego;
