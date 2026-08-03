//! Syndrome-Trellis Codes encoding and decoding.
//!
//! The coder is implemented in [`native`], in safe Rust and with no external
//! dependency. It replaces the FFI wrapper around libsdc++ this module carried
//! until PROMPT 6b; the public surface — [`stc_encode_safe`], [`stc_decode_safe`],
//! [`StcConfig`], [`StcError`] — is unchanged, so nothing above this layer
//! noticed the substitution.
//!
//! Implemented in PROMPT 6, replaced by a native implementation in PROMPT 6b.

pub mod native;

pub(crate) use native::{stc_decode_safe, stc_encode_safe};
pub use native::{StcConfig, StcError, DEFAULT_TRELLIS_HEIGHT, MAX_BPP};
