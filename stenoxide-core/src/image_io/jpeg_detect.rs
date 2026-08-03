//! Detection of prior JPEG compression via stochastic block sampling.
//!
//! A PNG that was produced by decoding a JPEG and re-encoding it losslessly is
//! not a clean container. The quantised DCT coefficients leave a footprint in
//! the pixel domain, and that footprint is one of the first things a steganalyst
//! looks for: any residual the embedder adds on top of it stands out against a
//! signal whose statistics are already known.
//!
//! # What is measured
//!
//! JPEG encodes the image as independent 8x8 blocks. Each block is quantised on
//! its own, so the reconstruction error does not agree across a block edge and
//! the decoded image carries a step at every eighth column and every eighth row
//! that the original scene never had. Inside a block there is no such step: the
//! inverse DCT is smooth there by construction.
//!
//! The detector compares those two populations of adjacent-pixel differences:
//!
//! ```text
//! ratio = mean |p(x, y) - p(x + 1, y)| over pairs straddling the 8x8 grid
//!         ────────────────────────────────────────────────────────────────
//!         mean |p(x, y) - p(x + 1, y)| over pairs strictly inside a block
//! ```
//!
//! An image that has never been through a lossy codec has no privileged
//! position: a pair on the grid line is statistically the same as a pair one
//! column over, and the ratio sits at about `1.0`. An image carrying JPEG
//! artifacts has a numerator inflated by the block edges, and the ratio climbs
//! well above it — measured at `1.77` for quality 90 and `10.4` for quality 50.
//!
//! The grid phase matters, and it is the whole signal: the measurement is only
//! meaningful because both sides know where the block edges are. That is also
//! why the detector cannot be fooled by a rescaled JPEG, and why it does not
//! claim to catch one.
//!
//! # Limitations
//!
//! The measurement is a ratio, so its sensitivity falls as the image's own
//! high-frequency energy rises: the codec's block edges have to be visible
//! against whatever the content already puts between neighbouring pixels. Two
//! cases were measured and do not trip the threshold.
//!
//! - Grain-dominated images at high quality. A container that is mostly noise
//!   of amplitude 30 scores `0.98` after a quality-90 round trip and only
//!   reaches `1.91` at quality 25. Quantisation that gentle barely moves a
//!   signal that random, so there is little to detect.
//! - Content built from very high-contrast axis-aligned edges. Steps of 180
//!   levels from the scene itself enter both populations and swamp a block edge
//!   worth a handful of levels.
//!
//! Both are the same limitation seen twice, and neither is a false *positive*:
//! the detector stays silent rather than rejecting a clean image. What it means
//! is that the gate is a filter and not a proof — it catches the laundered
//! JPEGs a user is likely to reach for by accident, not every one that exists.
//!
//! # Why the blocks are sampled and not scanned
//!
//! The verdict is a ratio of two means, and a mean converges long before the
//! whole image has been visited. Five per cent of the blocks — a few thousand
//! for a typical container — puts the standard error of the estimate far below
//! the distance between the two populations, at a fraction of the cost of a
//! full scan. The sample is drawn from a seed derived from the image itself, so
//! it is not a source of nondeterminism: the same image always yields the same
//! blocks and the same verdict.

use rand::rngs::StdRng;
use rand::seq::index;
use rand::SeedableRng;
use rayon::prelude::*;
use sha3::{Digest, Sha3_256};

use crate::image_io::buffer::ColorSpace;
use crate::image_io::phash::luminance;

/// Side length of the DCT grid JPEG quantises over, in pixels.
const BLOCK_SIZE: usize = 8;

/// Number of leading sample bytes hashed into the sampling seed.
const SEED_SAMPLE_LEN: usize = 1024;

/// Percentage of the blocks in the image that gets analysed.
const SAMPLE_PERCENT: usize = 5;

/// Lower bound on the number of sampled blocks.
const MIN_SAMPLES: usize = 50;

/// Upper bound on the number of sampled blocks.
const MAX_SAMPLES: usize = 10_000;

/// Ratio above which an image is reported as carrying JPEG artifacts.
///
/// A never-compressed image scores about `1.0`; the lowest JPEG quality that
/// still counts as a plausible container, 90, already scores `1.77`, and the
/// score grows from there as quality drops. The threshold sits deliberately
/// close to the clean end of a very wide gap, because the two failure modes are
/// not symmetric in cost — but not at `1.0` either: an image whose content
/// happens to carry strong axis-aligned edges can raise the numerator on its
/// own, without any codec involved, and `1.3` leaves room for that.
///
/// A false positive costs the user a container they were entitled to use, and
/// they can simply pick another one. A false negative hands a steganalyst an
/// image whose statistics they already know how to model.
const ARTIFACT_THRESHOLD: f32 = 1.3;

/// Guard against dividing by an interior energy of zero.
///
/// Deliberately the only protection against a flat denominator, and no minimum
/// interior activity is required on top of it. Heavy quantisation is exactly
/// what flattens the inside of a block while leaving the step at its edge
/// intact, so a sample with no interior texture and measurable boundaries is
/// not a sample that failed to produce evidence — it is the strongest evidence
/// of blocking there is, and the ratio it yields should be large. An image that
/// is flat everywhere, boundaries included, still scores zero and is accepted.
const DIVISION_EPSILON: f32 = 1e-6;

/// Absolute differences between neighbouring pixels, split by whether the pair
/// straddles a block boundary of the 8x8 grid.
///
/// Sums and counts are kept apart rather than pre-averaged so that the totals
/// of many blocks can be pooled into a single ratio. Pooling is what makes the
/// estimate robust: a per-block ratio would divide by the interior energy of
/// one 8x8 patch, which is zero on any flat patch and tiny on many, and the
/// mean of those ratios would be dominated by whichever block happened to be
/// smoothest rather than by the evidence.
#[derive(Default)]
struct StepEnergies {
    /// Sum of the steps that cross a grid line.
    boundary_sum: f32,
    /// Number of pairs in [`StepEnergies::boundary_sum`].
    boundary_pairs: usize,
    /// Sum of the steps strictly inside a block.
    interior_sum: f32,
    /// Number of pairs in [`StepEnergies::interior_sum`].
    interior_pairs: usize,
}

impl StepEnergies {
    /// Adds the totals of another block into this accumulator.
    fn absorb(&mut self, other: &StepEnergies) {
        self.boundary_sum += other.boundary_sum;
        self.boundary_pairs += other.boundary_pairs;
        self.interior_sum += other.interior_sum;
        self.interior_pairs += other.interior_pairs;
    }

    /// Mean boundary step divided by mean interior step.
    ///
    /// Returns `None` only when one of the two populations is empty, which
    /// means no block could be measured at all rather than that the blocks
    /// measured clean.
    fn ratio(&self) -> Option<f32> {
        if self.boundary_pairs == 0 || self.interior_pairs == 0 {
            return None;
        }

        let boundary = self.boundary_sum / self.boundary_pairs as f32;
        let interior = self.interior_sum / self.interior_pairs as f32;

        Some(boundary / (interior + DIVISION_EPSILON))
    }
}

/// Derives the block-sampling seed from the head of the sample buffer.
///
/// Hashing the image rather than drawing from the system entropy pool is what
/// makes the detector auditable: a rejected container can be re-tested and will
/// fail on exactly the same blocks. The leading bytes are enough because the
/// seed only has to vary between images, not to resist an adversary — nothing
/// downstream is protected by it.
fn sampling_seed(pixels: &[u8]) -> [u8; 32] {
    let head = &pixels[..SEED_SAMPLE_LEN.min(pixels.len())];

    let mut hasher = Sha3_256::new();
    hasher.update(head);
    hasher.finalize().into()
}

/// Converts the whole image to a row-major plane of BT.601 luma values.
///
/// Parallelised over pixels because this is the only part of the detector whose
/// cost scales with the image rather than with the sample: the block analysis
/// touches at most [`MAX_SAMPLES`] blocks, this touches every pixel.
/// Collecting an indexed parallel iterator preserves order, so the resulting plane
/// is laid out exactly as the sequential version would lay it out.
///
/// Shared with [`crate::cost::hill`], which runs its convolutions over the same
/// plane. Like [`luminance`] itself, it exists once so that the analyses of the
/// image cannot disagree about what the brightness of a pixel is.
pub(crate) fn luminance_plane(
    pixels: &[u8],
    pixel_count: usize,
    color_space: ColorSpace,
) -> Vec<f32> {
    let bytes_per_pixel = color_space.bytes_per_pixel();

    (0..pixel_count)
        .into_par_iter()
        .map(|index| {
            let offset = index * bytes_per_pixel;
            // In bounds for every index, because the caller has already checked
            // the buffer against `pixel_count * bytes_per_pixel`. Falling back
            // to black instead of indexing keeps the function total.
            pixels
                .get(offset..offset + bytes_per_pixel)
                .map_or(0.0, |sample| luminance(sample, color_space) as f32)
        })
        .collect()
}

/// Splits the adjacent-pixel steps of one 8x8 block into the two populations.
///
/// Each row of the block contributes seven interior steps and one step across
/// the vertical grid line at the right edge; each column contributes the same
/// down to the horizontal grid line at the bottom edge. Both directions are
/// measured because the JPEG grid is two-dimensional, and an image whose
/// texture runs in columns would hide its horizontal edges from a
/// one-directional scan.
///
/// The pair that straddles the right edge reaches into the neighbouring block
/// by one pixel. On a block sitting against the right or bottom border of the
/// image that pixel does not exist, and the step is dropped: the counts are
/// returned alongside the sums precisely so that a truncated block does not
/// weigh as much as a complete one.
fn block_energies(luma: &[f32], width: usize, height: usize, x0: usize, y0: usize) -> StepEnergies {
    let at = |x: usize, y: usize| luma.get(y * width + x).copied();
    let mut energies = StepEnergies::default();

    for index in 0..BLOCK_SIZE {
        // Horizontal steps along one row of the block.
        let y = y0 + index;
        for dx in 0..BLOCK_SIZE {
            let x = x0 + dx;
            // Bounds on `x` are checked explicitly rather than left to the
            // slice lookup: `y * width + x + 1` stays inside the plane when it
            // runs off the end of a row, and would silently compare a pixel
            // with the first pixel of the row below.
            if x + 1 >= width {
                break;
            }
            let (Some(here), Some(next)) = (at(x, y), at(x + 1, y)) else {
                break;
            };

            let step = (here - next).abs();
            if dx == BLOCK_SIZE - 1 {
                energies.boundary_sum += step;
                energies.boundary_pairs += 1;
            } else {
                energies.interior_sum += step;
                energies.interior_pairs += 1;
            }
        }

        // Vertical steps down one column of the block.
        let x = x0 + index;
        for dy in 0..BLOCK_SIZE {
            let y = y0 + dy;
            if y + 1 >= height {
                break;
            }
            let (Some(here), Some(below)) = (at(x, y), at(x, y + 1)) else {
                break;
            };

            let step = (here - below).abs();
            if dy == BLOCK_SIZE - 1 {
                energies.boundary_sum += step;
                energies.boundary_pairs += 1;
            } else {
                energies.interior_sum += step;
                energies.interior_pairs += 1;
            }
        }
    }

    energies
}

/// Estimates how strongly an image shows traces of a previous JPEG encoding.
///
/// Returns `Some(ratio)` when blocking artifacts are detected, where `ratio` is
/// the mean absolute difference between neighbouring pixels that straddle the
/// 8x8 grid, divided by the same mean taken strictly inside blocks, pooled over
/// the sampled blocks. Returns `None` when the image looks like it has never
/// been through a lossy codec, which is the case whenever that ratio stays at
/// or below the rejection threshold of `1.3`.
///
/// A value close to `1.0` means the grid lines are no sharper than the pixels
/// around them and the image carries no 8x8 block structure; the larger the
/// returned value, the stronger the structure.
///
/// `pixels` must hold `width * height * color_space.bytes_per_pixel()` bytes in
/// row-major order. `None` is returned for a buffer shorter than that and for
/// an image with no complete 8x8 block: in both cases there is nothing to
/// measure, and reporting a clean image is the answer that keeps the caller
/// from acting on a number that was never computed.
pub fn detect_jpeg_artifacts(
    pixels: &[u8],
    width: u32,
    height: u32,
    color_space: ColorSpace,
) -> Option<f32> {
    let width = width as usize;
    let height = height as usize;

    let pixel_count = width.checked_mul(height)?;
    let expected_len = pixel_count.checked_mul(color_space.bytes_per_pixel())?;
    if expected_len == 0 || pixels.len() < expected_len {
        return None;
    }

    let blocks_x = width / BLOCK_SIZE;
    let blocks_y = height / BLOCK_SIZE;
    let total_blocks = blocks_x.checked_mul(blocks_y)?;
    if total_blocks == 0 {
        return None;
    }

    // The clamp can ask for more blocks than the image has, on an image small
    // enough that five per cent of its blocks is under the floor of fifty.
    // Sampling without replacement cannot honour that, so the request is capped
    // at the population.
    let sample_size = total_blocks
        .saturating_mul(SAMPLE_PERCENT)
        .saturating_div(100)
        .clamp(MIN_SAMPLES, MAX_SAMPLES)
        .min(total_blocks);

    let luma = luminance_plane(pixels, pixel_count, color_space);
    let mut rng = StdRng::from_seed(sampling_seed(pixels));

    let mut pooled = StepEnergies::default();
    for block in index::sample(&mut rng, total_blocks, sample_size) {
        let x0 = (block % blocks_x) * BLOCK_SIZE;
        let y0 = (block / blocks_x) * BLOCK_SIZE;

        pooled.absorb(&block_energies(&luma, width, height, x0, y0));
    }

    pooled.ratio().filter(|&ratio| ratio > ARTIFACT_THRESHOLD)
}

#[cfg(test)]
mod tests {
    // The crate-wide ban on panicking helpers reaches into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so it is lifted here and only
    // here.
    #![allow(clippy::panic)]

    use super::*;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// Side length of the synthetic images below, in pixels.
    ///
    /// Eight blocks each way: enough that the sampler has a population to draw
    /// from, small enough that a test costs nothing.
    const SIDE: u32 = 64;

    /// A grayscale image built by a function of the coordinates.
    fn image_from<F: Fn(usize, usize) -> u8>(side: u32, level: F) -> Vec<u8> {
        let side = side as usize;

        (0..side * side)
            .map(|index| level(index % side, index / side))
            .collect()
    }

    /// Uncorrelated noise: no position in the 8x8 grid is privileged.
    fn clean_image(seed: u64) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(seed);

        (0..(SIDE * SIDE) as usize).map(|_| rng.random()).collect()
    }

    /// The luma plane is the image itself for a grayscale layout.
    #[test]
    fn the_luma_plane_reproduces_a_grayscale_image() {
        let pixels = image_from(4, |x, y| (x * 4 + y) as u8);
        let plane = luminance_plane(&pixels, 16, ColorSpace::Luma8);

        assert_eq!(plane.len(), 16);
        for (index, value) in plane.iter().enumerate() {
            assert_eq!(*value, pixels[index] as f32);
        }
    }

    /// The sampling seed is a function of the image, so a verdict can be
    /// reproduced on exactly the blocks that produced it.
    #[test]
    fn the_sampling_seed_follows_the_image() {
        let first = clean_image(1);
        let second = clean_image(2);

        assert_eq!(sampling_seed(&first), sampling_seed(&first));
        assert_ne!(sampling_seed(&first), sampling_seed(&second));
    }

    /// A ratio of two means needs both populations to be non-empty.
    #[test]
    fn an_empty_population_yields_no_ratio() {
        assert!(StepEnergies::default().ratio().is_none());

        let boundary_only = StepEnergies {
            boundary_sum: 10.0,
            boundary_pairs: 4,
            interior_sum: 0.0,
            interior_pairs: 0,
        };
        assert!(boundary_only.ratio().is_none());
    }

    /// An image whose steps do not care about the grid is reported clean.
    #[test]
    fn uncorrelated_noise_shows_no_block_structure() {
        assert_eq!(
            detect_jpeg_artifacts(&clean_image(3), SIDE, SIDE, ColorSpace::Luma8),
            None
        );
    }

    /// An image built as constant 8x8 tiles is the block structure the detector
    /// exists to find: every step it shows sits on a grid line.
    #[test]
    fn tiled_content_is_reported_as_blocking() {
        let tiled = image_from(SIDE, |x, y| {
            if (x / 8 + y / 8) % 2 == 0 {
                100
            } else {
                160
            }
        });

        match detect_jpeg_artifacts(&tiled, SIDE, SIDE, ColorSpace::Luma8) {
            Some(ratio) => assert!(ratio > ARTIFACT_THRESHOLD, "ratio was {ratio}"),
            None => panic!("a tiled image must be reported as blocking"),
        }
    }

    /// Nothing to measure is answered with "clean" rather than with a number
    /// that was never computed.
    #[test]
    fn there_is_no_verdict_without_a_complete_block() {
        // No pixels at all.
        assert_eq!(
            detect_jpeg_artifacts(&[], 0, 0, ColorSpace::Rgb8),
            None
        );

        // A buffer shorter than the geometry it claims.
        assert_eq!(
            detect_jpeg_artifacts(&[0u8; 10], SIDE, SIDE, ColorSpace::Luma8),
            None
        );

        // Large enough to fill its buffer, too small to hold one 8x8 block.
        assert_eq!(
            detect_jpeg_artifacts(&[0u8; 16], 4, 4, ColorSpace::Luma8),
            None
        );
    }
}
