//! Deterministic generation of the container fixtures the integration tests
//! share.
//!
//! Nothing under `tests/fixtures/` is committed. Every fixture is built from a
//! fixed seed the first time a test asks for it, so the suite carries no binary
//! blobs, and a fixture that no longer produces the property a test relies on
//! fails visibly here rather than silently going stale in the repository.
//!
//! # What each fixture has to satisfy
//!
//! The three validation gates of layer 1 and the two of layer 3 pull in
//! different directions, and the covers below are shaped by that:
//!
//! - **Perceptual stability.** [`compute_stable_phash`] hashes a 32x32
//!   thumbnail and refuses any image with more than one DCT coefficient within
//!   `5.0` of the median. Gaussian grain on a flat background cannot satisfy
//!   this: a 2000x2000 image collapses to 32x32 by averaging some four thousand
//!   pixels per output sample, which drives the grain's contribution to well
//!   under one coefficient unit and leaves all 64 AC coefficients piled up
//!   around a near-zero median. The cover therefore carries a low-frequency
//!   random field *underneath* the grain — structure coarse enough to survive
//!   the downscale is the only thing that spreads those coefficients out.
//! - **Texture.** The HILL gate refuses an image whose 95th-percentile cost
//!   falls below `0.10`, i.e. one that is high-energy everywhere. Grain of
//!   standard deviation two sits comfortably on the accepting side.
//! - **No JPEG grid.** The block-boundary detector of layer 1 rejects anything
//!   scoring above `1.3`. The field is interpolated smoothly rather than
//!   drawn as blocks, so the cover introduces no periodic step of its own.
//!
//! [`compute_stable_phash`]: stenoxide_core::image_io::phash::compute_stable_phash

// Cargo compiles this module separately into every integration binary that
// declares it, and each of those uses a different part of it — `crypto.rs` only
// wants the cover, `integration.rs` wants all three fixtures. Anything the
// binary being compiled does not touch would otherwise be reported as dead,
// which is a fact about that one binary rather than about this file.
#![allow(dead_code)]

use std::f32::consts::TAU;
use std::path::{Path, PathBuf};
use std::sync::Once;

use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType, ImageFormat, RgbImage};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

/// Side length of the covers, in pixels.
///
/// Exactly the minimum layer 1 accepts, so the fixtures also pin that boundary:
/// a container one pixel smaller would be refused.
pub const COVER_SIDE: u32 = 2000;

/// Side length of the control grid of the low-frequency field.
///
/// Deliberately the side of the perceptual-hash thumbnail. One control point
/// per thumbnail sample is what puts energy in every coefficient the hash
/// reads, including the highest horizontal frequency it looks at.
const FIELD_GRID: usize = 32;

/// Peak deviation of the low-frequency field from mid grey, in levels.
///
/// Large enough that the AC coefficients of the thumbnail land two orders of
/// magnitude above the `5.0` stability margin, small enough that grain never
/// pushes a sample out of range and gets clipped.
const FIELD_AMPLITUDE: f32 = 95.0;

/// Share of a field cell spent easing from one control value to the next.
///
/// See [`sample_field`]: the remaining two thirds of the cell are flat, which
/// is what lets the perceptual-hash thumbnail see the control values themselves
/// rather than a heavily smoothed version of them.
const FIELD_EDGE_WIDTH: f32 = 0.25;

/// Standard deviation of the grain added on top of the field, in levels.
///
/// The quantity the HILL cost map actually measures. Two levels keeps the
/// 95th-percentile cost well above the `0.10` texture floor; raising it towards
/// four would start pressing against that gate from the other side.
const GRAIN_SIGMA: f32 = 2.0;

/// Seed of the cover fixture.
///
/// Not arbitrary. The stability gate compares each of the 64 AC coefficients
/// against their median, and the median is the midpoint of the two central
/// ones — so those two are always equidistant from it, and the image is
/// accepted precisely when the gap between them exceeds twice the `5.0`
/// threshold. For a field of this amplitude the gap averages a few tens of
/// units, which makes acceptance a coin toss on an arbitrary seed. This one was
/// picked out of four hundred candidates for a gap of about `84`, leaving every
/// bit a margin of some `42` units: eight times the threshold, and eight orders
/// of magnitude above what embedding perturbs a thumbnail sample by.
const COVER_SEED: u64 = 337;

/// Seed of the photographic content behind the disguised JPEG.
const PHOTO_SEED: u64 = 0x4A50_4547_5F41_5350;

/// Seed of the incompressible payload.
const PAYLOAD_SEED: u64 = 0x5041_594C_4F41_4421;

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
/// invocation of the test binary: regenerating three images costs a second or
/// two, and a cache that could hold a fixture built by an older version of this
/// file would be worth far less than that.
pub fn ensure_fixtures() {
    FIXTURES.call_once(|| {
        let dir = fixtures_dir();
        std::fs::create_dir_all(&dir).expect("fixtures directory should be creatable");

        cover_image(COVER_SEED, COVER_SIDE)
            .save_with_format(dir.join("texture_2000x2000.png"), ImageFormat::Png)
            .expect("textured cover should be writable");

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
///
/// The capacity gate measures the payload *after* compression, so a test that
/// wants to overflow a container has to hand it something incompressible.
/// Anything with structure — a run of zeros, a counter, a byte pattern with a
/// short period — is compressed to a few dozen bytes at level 19 and sails
/// through the very check it was meant to trip.
pub fn incompressible_payload(len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(PAYLOAD_SEED);

    (0..len).map(|_| rng.random()).collect()
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

/// The textured cover: a mottled random field with photographic grain on top.
///
/// Parameterised by seed and side length because choosing [`COVER_SEED`] means
/// searching for one: build the image for a few hundred candidate seeds, take
/// the luma thumbnail and its DCT as [`compute_stable_phash`] does, and keep the
/// seed whose two central AC coefficients are furthest apart. A 640x640 scale
/// model — same 32 cells, same shoulder proportion — ranks candidates at a
/// fortieth of the cost, and the winner is then confirmed at full size.
///
/// [`compute_stable_phash`]: stenoxide_core::image_io::phash::compute_stable_phash
fn cover_image(seed: u64, side: u32) -> RgbImage {
    let mut rng = StdRng::seed_from_u64(seed);

    // One control grid per channel, so the three planes are not scaled copies
    // of one another. A cover whose channels were perfectly correlated would be
    // an odd thing to hand a Colour Rich Model, and the red-channel penalty of
    // the cost layer would have nothing to distinguish.
    let planes: Vec<Vec<f32>> = (0..3).map(|_| control_grid(&mut rng)).collect();

    RgbImage::from_fn(side, side, |x, y| {
        let mut channels = [0u8; 3];
        for (channel, plane) in channels.iter_mut().zip(planes.iter()) {
            let level =
                128.0 + sample_field(plane, x, y, side) + gaussian(&mut rng, GRAIN_SIGMA);
            *channel = level.clamp(0.0, 255.0) as u8;
        }

        image::Rgb(channels)
    })
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

/// Draws the `FIELD_GRID + 1` square control grid of the low-frequency field.
///
/// One extra row and column so that [`sample_field`] always has a cell to the
/// right and below the sample it is interpolating, including on the last pixel
/// of the image.
/// Control values are two-valued rather than drawn from the whole range. A
/// uniform draw has a standard deviation of only `amplitude / sqrt(3)`, and
/// every unit of that spread is a unit of margin the stability gate measures;
/// putting all the mass at the extremes buys a factor of `sqrt(3)` for free,
/// against a clipping budget that is what limits the amplitude in the first
/// place.
fn control_grid(rng: &mut StdRng) -> Vec<f32> {
    let side = FIELD_GRID + 1;

    (0..side * side)
        .map(|_| {
            if rng.random_bool(0.5) {
                FIELD_AMPLITUDE
            } else {
                -FIELD_AMPLITUDE
            }
        })
        .collect()
}

/// Interpolates the control grid at an image coordinate.
///
/// Neither a hard mosaic nor a smooth blend, but a plateau with an eased
/// shoulder, and the width of that shoulder is the whole design of this
/// fixture. It sets where the cover lands between two gates that want opposite
/// things:
///
/// - Interpolating across the full cell attenuates the thumbnail's high
///   frequencies badly. Measured that way the 64 hash coefficients had a
///   standard deviation of some 250 units, four of them fell inside the `5.0`
///   margin, and the cover was refused as perceptually unstable.
/// - Not interpolating at all leaves a step at every cell edge. Cells are 62.5
///   pixels wide against a JPEG grid of 8, so those steps would walk through
///   every phase of the grid and inflate the boundary population the artifact
///   detector measures.
///
/// A shoulder of [`FIELD_EDGE_WIDTH`] resolves both: each cell keeps a flat
/// interior, so the 32x32 thumbnail reproduces the control value almost
/// unattenuated, while the transition is spread over some twenty pixels and no
/// pair of adjacent pixels anywhere in the image carries a step.
fn sample_field(grid: &[f32], x: u32, y: u32, side: u32) -> f32 {
    let scale = FIELD_GRID as f32 / side as f32;
    let fx = x as f32 * scale;
    let fy = y as f32 * scale;

    let x0 = fx as usize;
    let y0 = fy as usize;
    let tx = shoulder(fx - x0 as f32);
    let ty = shoulder(fy - y0 as f32);

    let stride = FIELD_GRID + 1;
    let at = |gx: usize, gy: usize| grid.get(gy * stride + gx).copied().unwrap_or(0.0);

    let top = at(x0, y0) * (1.0 - tx) + at(x0 + 1, y0) * tx;
    let bottom = at(x0, y0 + 1) * (1.0 - tx) + at(x0 + 1, y0 + 1) * tx;

    top * (1.0 - ty) + bottom * ty
}

/// Maps a position within a cell onto the eased shoulder of [`sample_field`].
///
/// Everything outside the middle [`FIELD_EDGE_WIDTH`] of the cell is clamped to
/// one endpoint or the other; the band in between runs through the classic
/// `3t^2 - 2t^3` ease, whose derivative vanishes at both ends and therefore
/// joins the two plateaus without a crease.
fn shoulder(t: f32) -> f32 {
    let eased = ((t - 0.5) / FIELD_EDGE_WIDTH + 0.5).clamp(0.0, 1.0);

    eased * eased * (3.0 - 2.0 * eased)
}

/// One normally distributed sample of standard deviation `sigma`, by
/// Box-Muller.
///
/// Only the cosine half of the transform is kept and the sine half discarded.
/// Storing the spare would make the function stateful, and the grain is drawn
/// four million times per channel from a seeded generator — the sequence has to
/// depend on the seed alone, not on how the caller happens to interleave its
/// calls.
fn gaussian(rng: &mut StdRng, sigma: f32) -> f32 {
    // Bounded away from zero: `ln(0)` is negative infinity, and a single
    // infinite grain sample would clip to a black or white pixel.
    let uniform: f32 = rng.random_range(f32::EPSILON..1.0);
    let angle: f32 = rng.random_range(0.0..TAU);

    sigma * (-2.0 * uniform.ln()).sqrt() * angle.cos()
}
