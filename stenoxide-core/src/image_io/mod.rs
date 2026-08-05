//! Layer 1 — image input/output.
//!
//! Loads the container image, validates it through a type-state pipeline and
//! analyses it for traces of lossy compression. The type-state pattern
//! guarantees that no downstream layer can ever receive an image that has not
//! passed every validation gate.
//!
//! Loading also records the shape of the file the samples came in — see
//! [`envelope`] — because a container is given away by its wrapper as readily as
//! by its pixels, and the wrapper is the cheaper of the two to read.

pub mod buffer;
pub mod envelope;
pub mod jpeg_detect;
pub mod phash;
pub mod validate;
