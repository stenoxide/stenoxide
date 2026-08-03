//! Layer 1 — image input/output.
//!
//! Loads the container image, validates it through a type-state pipeline and
//! analyses it for traces of lossy compression. The type-state pattern
//! guarantees that no downstream layer can ever receive an image that has not
//! passed every validation gate.

pub mod buffer;
pub mod jpeg_detect;
pub mod phash;
pub mod validate;
