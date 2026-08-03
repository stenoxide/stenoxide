//! Syndrome-Trellis Codes encoding and decoding.
//!
//! The safe surface of the STC coder. All interaction with the external
//! libsdc++ library is confined to the [`ffi`] submodule.
//!
//! Implemented in PROMPT 6.

pub mod ffi;
