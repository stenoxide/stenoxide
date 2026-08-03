//! Detection of prior JPEG compression via stochastic block sampling.
//!
//! The real implementation lands in PROMPT 4. Until then the detector is a
//! stub that reports "no artifacts", which keeps the validation type-state in
//! [`crate::image_io::validate`] compiling and exercising the full chain of
//! transitions.

use crate::image_io::buffer::ColorSpace;

/// Estimates how strongly an image shows traces of a previous JPEG encoding.
///
/// Returns `Some(ratio)` when blocking artifacts are detected, where `ratio` is
/// the fraction of sampled 8x8 blocks whose boundaries show the discontinuity
/// signature of quantised DCT coefficients. Returns `None` when the image looks
/// like it has never been through a lossy codec.
pub fn detect_jpeg_artifacts(
    _pixels: &[u8],
    _width: u32,
    _height: u32,
    _color_space: ColorSpace,
) -> Option<f32> {
    // Real implementation in PROMPT 4.
    None
}
