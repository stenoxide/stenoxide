//! Layer 3 — adaptive cost analysis.
//!
//! Builds the HILL cost map used to steer embedding towards textured regions.
//! The `'img` lifetime carried by the cost map ties it to the borrow of the
//! validated image buffer, so the compiler — not convention — guarantees that
//! the pixels cannot be mutated while the map is alive.
//!
//! Implemented in PROMPT 5.

pub mod hill;
