//! Deterministic generation of the container fixtures the integration tests
//! share.
//!
//! Nothing under `tests/fixtures/` is committed. Every fixture is built from a
//! fixed seed the first time a test asks for it, so the suite carries no binary
//! blobs, and a fixture that no longer produces the property a test relies on
//! fails visibly here rather than silently going stale in the repository.
//!
//! The covers themselves come from [`stenoxide_core::test_support`], which is
//! where the shape of a container this system accepts is defined. This module
//! is the caching layer over it, plus the fixtures that exist to be *refused*.

// Cargo compiles this module separately into every integration binary that
// declares it, and each of those uses a different part of it — `crypto.rs` only
// wants the cover, `integration.rs` wants all of them. Anything the binary
// being compiled does not touch would otherwise be reported as dead, which is a
// fact about that one binary rather than about this file.
#![allow(dead_code)]

use std::f32::consts::TAU;
use std::path::{Path, PathBuf};
use std::sync::Once;

use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType, ImageFormat, RgbImage};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use stenoxide_core::test_support;

/// Side length of the covers, in pixels.
pub const COVER_SIDE: u32 = test_support::COVER_SIDE;

/// Seed the first cover is searched from.
///
/// Acceptance is close to a coin toss on an arbitrary seed — see
/// [`stenoxide_core::test_support::stable_cover`] — and this one passes on its
/// first candidate, with the two central AC coefficients some `84` units apart:
/// eight times the stability threshold, and eight orders of magnitude above
/// what embedding perturbs a thumbnail sample by.
const COVER_SEED: u64 = 337;

/// Seed the second cover is searched from.
///
/// Far from the first, so that the two searches cannot converge on one image
/// however many candidates either of them has to reject.
const ALTERNATIVE_COVER_SEED: u64 = 1_000;

/// Seed of the photographic content behind the disguised JPEG.
const PHOTO_SEED: u64 = 0x4A50_4547_5F41_5350;

/// JPEG quality the disguised fixture is compressed at.
///
/// The reference measurements for this kind of content put quality 75 at a
/// blocking ratio of about `3.3`, comfortably above the `1.3` rejection
/// threshold and far enough from it that the fixture does not depend on the
/// exact encoder build.
const DISGUISE_QUALITY: u8 = 75;

/// Quality of the small honest JPEG.
///
/// Irrelevant to what that fixture tests — magic-byte detection happens before
/// a single pixel is decoded — but a plausible value keeps the file honest.
const CLEAN_JPEG_QUALITY: u8 = 90;

/// Side length of the small honest JPEG, in pixels.
const CLEAN_JPEG_SIDE: u32 = 64;

/// Runs the fixture generation exactly once per test binary.
static FIXTURES: Once = Once::new();

/// Directory the fixtures live in.
///
/// Anchored at the manifest directory rather than at the working directory:
/// both happen to be the package root when `cargo test` runs the binary, but
/// only the first is guaranteed to be.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// The textured cover used by the round trip, the capacity and the stability
/// tests.
pub fn textured_cover() -> PathBuf {
    ensure_fixtures();
    fixtures_dir().join("texture_2000x2000.png")
}

/// A second textured cover, indistinguishable from the first in every property
/// the gates measure and different in every sample.
///
/// What it is for: the salt is the container's perceptual hash, so the same
/// password applied to two different images must produce two different keys.
/// Showing that needs a second image that is a legitimate container in its own
/// right — anything the loader would have refused would prove nothing.
pub fn alternative_cover() -> PathBuf {
    ensure_fixtures();
    fixtures_dir().join("texture_alternative.png")
}

/// A small, honest JPEG. Used to check that magic bytes alone are enough.
pub fn clean_jpeg() -> PathBuf {
    ensure_fixtures();
    fixtures_dir().join("clean.jpg")
}

/// JPEG-compressed content re-encoded losslessly as a PNG.
///
/// The magic bytes say PNG and the pixels say otherwise, which is precisely
/// what the third validation gate exists to catch.
pub fn jpeg_as_png() -> PathBuf {
    ensure_fixtures();
    fixtures_dir().join("jpeg_as_png.png")
}

/// Builds every fixture, once.
///
/// Idempotent across threads through [`Once`], and re-run from scratch on every
/// invocation of the test binary: regenerating the images costs a few seconds,
/// and a cache that could hold a fixture built by an older version of this file
/// would be worth far less than that.
pub fn ensure_fixtures() {
    FIXTURES.call_once(|| {
        let dir = fixtures_dir();
        std::fs::create_dir_all(&dir).expect("fixtures directory should be creatable");

        test_support::write_stable_cover(&dir.join("texture_2000x2000.png"), COVER_SEED);
        test_support::write_stable_cover(
            &dir.join("texture_alternative.png"),
            ALTERNATIVE_COVER_SEED,
        );

        write_jpeg(
            &gradient_image(CLEAN_JPEG_SIDE, CLEAN_JPEG_SIDE),
            CLEAN_JPEG_QUALITY,
            &dir.join("clean.jpg"),
        );

        laundered_jpeg()
            .save_with_format(dir.join("jpeg_as_png.png"), ImageFormat::Png)
            .expect("disguised jpeg should be writable");
    });
}

/// A deterministic byte string that Zstandard cannot shrink.
pub fn incompressible_payload(len: usize) -> Vec<u8> {
    test_support::incompressible_payload(len)
}

/// Writes a 500x500 PNG to `path`.
///
/// Used by the minimum-size test, which needs a file that is a valid PNG in
/// every respect except its dimensions — anything the decoder itself rejected
/// would prove nothing about the size gate.
pub fn write_undersized_png(path: &Path) {
    gradient_image(500, 500)
        .save_with_format(path, ImageFormat::Png)
        .expect("undersized png should be writable");
}

/// Writes a file whose magic number identifies it as a WebP.
///
/// The bytes after the twelve-byte header are never read: the format gate
/// refuses the file before any of it reaches a decoder.
pub fn write_webp_header(path: &Path) {
    let mut bytes = b"RIFF".to_vec();
    bytes.extend_from_slice(&[0x20, 0, 0, 0]);
    bytes.extend_from_slice(b"WEBPVP8 ");

    std::fs::write(path, bytes).expect("webp header should be writable");
}

/// Writes bytes that are not any format the loader can name.
pub fn write_unknown_format(path: &Path) {
    std::fs::write(path, b"not an image, not a format, just bytes")
        .expect("unknown format should be writable");
}

/// Writes an honest PNG signature over a stream that is not a PNG.
///
/// The complement of [`write_unknown_format`]: the format gate passes and the
/// decoder is the one that has to refuse.
pub fn write_corrupt_png(path: &Path) {
    let mut bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    bytes.extend_from_slice(&[0x42; 128]);

    std::fs::write(path, bytes).expect("corrupt png should be writable");
}

/// Writes a container of the right size in a pixel layout the embedder cannot
/// use.
///
/// Grayscale with an alpha channel. Flat rather than textured because nothing
/// past the layout check is reached, and a uniform image of this size costs a
/// few kilobytes instead of several megabytes.
pub fn write_grayscale_alpha_png(path: &Path) {
    image::GrayAlphaImage::from_pixel(COVER_SIDE, COVER_SIDE, image::LumaA([110, 255]))
        .save_with_format(path, ImageFormat::Png)
        .expect("grayscale-alpha png should be writable");
}

/// Writes a container of the right size with no texture anywhere.
///
/// Passes every gate of layer 1 — it is a PNG, it is large enough, and a
/// uniform image carries no block structure — and fails the first thing that
/// asks anything of its content.
pub fn write_flat_png(path: &Path) {
    RgbImage::from_pixel(COVER_SIDE, COVER_SIDE, image::Rgb([128, 128, 128]))
        .save_with_format(path, ImageFormat::Png)
        .expect("flat png should be writable");
}

/// Content of the kind the block detector was tuned against, put through a
/// JPEG round trip and handed back as raw samples.
///
/// Photographic rather than grainy on purpose. A grain-dominated image masks
/// the codec's block steps with noise of its own and is *accepted* even after
/// heavy compression — measured at `0.98` for quality 75 — so a fixture built by
/// compressing the textured cover would silently test nothing. Smooth structure
/// with one hard edge and grain of amplitude three is what puts the ratio in the
/// range the gate was designed for.
fn laundered_jpeg() -> RgbImage {
    let mut rng = StdRng::seed_from_u64(PHOTO_SEED);
    let source = RgbImage::from_fn(COVER_SIDE, COVER_SIDE, |x, y| {
        let fx = x as f32 / COVER_SIDE as f32;
        let fy = y as f32 / COVER_SIDE as f32;

        // Crossed sinusoids of a few cycles across the frame: low-frequency
        // structure the quantiser leaves almost untouched inside a block, so
        // every step the decoded image shows at a grid line came from the codec.
        let base = 128.0 + 45.0 * (TAU * 1.5 * fx).sin() + 35.0 * (TAU * 2.0 * fy).cos();

        // One hard edge. Real photographs have them, and they are what forces
        // the encoder to spend its ringing budget somewhere.
        let edge = if x > COVER_SIDE * 3 / 5 && y > COVER_SIDE / 4 {
            40.0
        } else {
            0.0
        };

        let grain: f32 = rng.random_range(-3.0..=3.0);
        let level = (base + edge + grain).clamp(0.0, 255.0) as u8;

        image::Rgb([level, level.saturating_sub(6), level.saturating_add(4)])
    });

    let mut encoded = Vec::new();
    JpegEncoder::new_with_quality(&mut encoded, DISGUISE_QUALITY)
        .encode(
            source.as_raw(),
            COVER_SIDE,
            COVER_SIDE,
            ExtendedColorType::Rgb8,
        )
        .expect("photographic source should be jpeg-encodable");

    image::load_from_memory_with_format(&encoded, ImageFormat::Jpeg)
        .expect("freshly encoded jpeg should decode")
        .to_rgb8()
}

/// A plain diagonal gradient. Content is irrelevant wherever this is used.
fn gradient_image(width: u32, height: u32) -> RgbImage {
    RgbImage::from_fn(width, height, |x, y| {
        let level = ((x + y) % 256) as u8;

        image::Rgb([level, level / 2, 255 - level])
    })
}

/// Encodes `image` as a JPEG at `quality` and writes it to `path`.
fn write_jpeg(image: &RgbImage, quality: u8, path: &Path) {
    let mut encoded = Vec::new();
    JpegEncoder::new_with_quality(&mut encoded, quality)
        .encode(
            image.as_raw(),
            image.width(),
            image.height(),
            ExtendedColorType::Rgb8,
        )
        .expect("gradient should be jpeg-encodable");

    std::fs::write(path, encoded).expect("jpeg fixture should be writable");
}
