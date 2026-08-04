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
//! Beside them, and composed of the same parts, [`generate`] builds a container
//! *around* a payload rather than hiding a payload inside one. It is a second
//! entry point rather than a sixth layer: it reuses layers 1 and 2 whole, and
//! layers 3 and 4 take no part in it at all, because there is no cost to
//! minimise when every position of a container one draws oneself is equally
//! free.
//!
//! ## Linting policy
//!
//! Fallible operations must be expressed through `Result`. Panicking helpers and
//! `unsafe` are denied crate-wide, without exception: the Syndrome-Trellis coder
//! was the one module that used to re-enable `unsafe` locally, and it is now
//! [`stego::stc::native`], which is safe Rust and links nothing.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(missing_docs)]

pub mod cost;
pub mod crypto;
pub mod generate;
pub mod image_io;
pub mod pipeline;
pub mod stego;

// Container fixtures, shared by the test suites of both crates so that there is
// one definition of "an image this system accepts". Compiled only under the
// `test-utils` feature, which no release build turns on.
#[cfg(feature = "test-utils")]
pub mod test_support;
