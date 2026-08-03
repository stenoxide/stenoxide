//! Layer 4 — embedding.
//!
//! Fisher-Yates permutation seeded by the STC key, capacity validation against
//! the `max_bpp` hard limit, and the Syndrome-Trellis Codes encode/decode
//! wrapper.
//!
//! Implemented in PROMPT 6.

pub mod permute;
pub mod sizer;
pub mod stc;
