//! Layer 5 — pipeline orchestration.
//!
//! Chains layers 1 to 4 with explicit ownership transfer at every step, so
//! each sensitive buffer is dropped and zeroed at the earliest possible point.
//! The extraction path needs no cost map: STC decoding operates on the
//! syndrome of all pixels rather than on a stored position list.
//!
//! Implemented in PROMPT 7.
