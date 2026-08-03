//! Container fixtures shared by the test suites of this workspace.
//!
//! Compiled only under the `test-utils` feature, which no release build turns
//! on. It exists because building a container that passes every gate is not a
//! two-line job — see [`stable_cover`] — and both crates of the workspace need
//! one: the core suite to drive the pipeline, and the front-end suite to have
//! something for `scan` to accept.
//!
//! # What a usable container has to satisfy
//!
//! The gates of layer 1 and layer 3 pull in different directions, and the cover
//! below is shaped by that:
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
//!   scoring above `1.3`. The field is interpolated smoothly rather than drawn
//!   as blocks, so the cover introduces no periodic step of its own.
//!
//! [`compute_stable_phash`]: crate::image_io::phash::compute_stable_phash

// This module is the one place in `src/` that may panic. It builds fixtures for
// a test to consume, and a fixture that cannot be built is a test that cannot
// run: propagating an error would only move the failure to a caller whose only
// sensible reaction is the same one. The lints stay in force everywhere else.
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::f32::consts::TAU;
use std::path::Path;

use image::{ImageFormat, RgbImage};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use crate::cost::hill::HillCostProvider;
use crate::cost::CostProvider;
use crate::image_io::buffer::{ColorSpace, ImageBuffer};
use crate::image_io::phash::compute_stable_phash;

/// Side length of the covers, in pixels.
///
/// Exactly the minimum layer 1 accepts, so a fixture built here also pins that
/// boundary: a container one pixel smaller would be refused.
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

/// Candidate seeds [`stable_cover`] will try before giving up.
const MAX_CANDIDATES: u64 = 64;

/// Builds a container that passes every gate, and reports the seed it took.
///
/// # Why this is a search and not a constant
///
/// The stability gate compares each of the 64 AC coefficients against their
/// median, and the median is the midpoint of the two central ones — so those
/// two are always equidistant from it, and the image is accepted precisely when
/// the gap between them exceeds twice the `5.0` threshold. For a field of this
/// amplitude the gap averages a few tens of units, which makes acceptance close
/// to a coin toss on an arbitrary seed. Pinning a literal would work until the
/// day a dependency changed a rounding somewhere; searching upwards from a seed
/// costs one candidate when nothing has drifted and repairs itself when
/// something has.
///
/// Candidates are judged in memory, against the same two providers the pipeline
/// uses. Nothing is written until one passes.
///
/// # Panics
///
/// Panics when no candidate in [`MAX_CANDIDATES`] passes, which would mean the
/// generator no longer produces containers this crate accepts at all.
pub fn stable_cover(seed: u64) -> (RgbImage, u64) {
    for candidate in seed..seed + MAX_CANDIDATES {
        let image = cover_image(candidate, COVER_SIDE);
        let buffer = ImageBuffer::new(
            image.as_raw().clone(),
            COVER_SIDE,
            COVER_SIDE,
            ColorSpace::Rgb8,
        );

        if compute_stable_phash(&buffer).is_ok() && HillCostProvider::new().compute(&buffer).is_ok()
        {
            return (image, candidate);
        }
    }

    panic!("no usable cover found in {MAX_CANDIDATES} candidates from seed {seed}")
}

/// Writes the container [`stable_cover`] found to `path`, as a PNG.
///
/// # Panics
///
/// Panics when the file cannot be written; see [`stable_cover`] for the other
/// way this can fail.
pub fn write_stable_cover(path: &Path, seed: u64) {
    let (image, _seed) = stable_cover(seed);

    image
        .save_with_format(path, ImageFormat::Png)
        .expect("cover should be writable");
}

/// A deterministic byte string that Zstandard cannot shrink.
///
/// The capacity gate measures the payload *after* compression, so a test that
/// wants to fill or overflow a container has to hand it something
/// incompressible. Anything with structure — a run of zeros, a counter, a byte
/// pattern with a short period — is compressed to a few dozen bytes at level 19
/// and sails through the very check it was meant to exercise.
pub fn incompressible_payload(len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(PAYLOAD_SEED);

    (0..len).map(|_| rng.random()).collect()
}

/// Seed of the incompressible payload.
const PAYLOAD_SEED: u64 = 0x5041_594C_4F41_4421;

/// The textured cover: a mottled random field with photographic grain on top.
///
/// Parameterised by seed and side length because choosing a good seed means
/// searching for one; see [`stable_cover`].
pub fn cover_image(seed: u64, side: u32) -> RgbImage {
    let mut rng = StdRng::seed_from_u64(seed);

    // One control grid per channel, so the three planes are not scaled copies
    // of one another. A cover whose channels were perfectly correlated would be
    // an odd thing to hand a Colour Rich Model, and the red-channel penalty of
    // the cost layer would have nothing to distinguish.
    let planes: Vec<Vec<f32>> = (0..3).map(|_| control_grid(&mut rng)).collect();

    RgbImage::from_fn(side, side, |x, y| {
        let mut channels = [0u8; 3];
        for (channel, plane) in channels.iter_mut().zip(planes.iter()) {
            let level = 128.0 + sample_field(plane, x, y, side) + gaussian(&mut rng, GRAIN_SIGMA);
            *channel = level.clamp(0.0, 255.0) as u8;
        }

        image::Rgb(channels)
    })
}

/// Draws the `FIELD_GRID + 1` square control grid of the low-frequency field.
///
/// One extra row and column so that [`sample_field`] always has a cell to the
/// right and below the sample it is interpolating, including on the last pixel
/// of the image.
///
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
