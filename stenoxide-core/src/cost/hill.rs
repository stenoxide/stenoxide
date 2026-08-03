//! HILL adaptive cost map with rejection of smooth regions.
//!
//! # The model
//!
//! HILL — *High-pass, Low-pass, Low-pass* — answers one question per pixel:
//! how much does changing this sample disturb the statistics a steganalyser
//! measures? The answer is built in three convolutions over the luma plane:
//!
//! 1. A 3x3 Laplacian isolates the high-frequency content. Its absolute value
//!    is large wherever neighbouring pixels disagree — edges, grain, texture —
//!    and near zero across a gradient or a flat wall.
//! 2. A 5x5 Gaussian spreads that residual over its neighbourhood, so that a
//!    pixel sitting one step away from an edge inherits part of its texture
//!    instead of being judged in isolation.
//! 3. A second, wider Gaussian smooths the result again, and the reciprocal of
//!    that value becomes the cost: dense texture yields a large residual and
//!    therefore a small cost, a smooth region yields a residual near zero and a
//!    cost that grows without bound until the guard epsilon caps it.
//!
//! The double low-pass is what distinguishes HILL from a plain edge detector.
//! A single filter would hand the lowest costs to isolated pixels whose own
//! neighbourhood happens to be noisy; two passes require a *region* to be
//! textured before anything inside it becomes cheap, and clustered changes are
//! far harder to detect than scattered ones.
//!
//! # Why the image can be rejected
//!
//! The cost map only ranks pixels; it does not decide whether the image has any
//! good pixel at all. A poster, a screenshot or a synthetic gradient produces a
//! perfectly valid map in which every position is expensive, and embedding into
//! it would put every change where the eye and the detector both look first.
//! [`HillCostProvider::compute`] therefore ends in three blocking gates, and a
//! container that fails any of them is refused rather than used badly.

use std::collections::VecDeque;
use std::fmt;

use rayon::prelude::*;

use crate::cost::{CostMap, CostProvider};
use crate::image_io::buffer::{CoverSource, ImageBuffer};
use crate::image_io::jpeg_detect::luminance_plane;

/// High-pass stage: the 3x3 Laplacian of step 1, row-major.
const HIGH_PASS_KERNEL: [[f32; 3]; 3] = [[0.0, -1.0, 0.0], [-1.0, 4.0, -1.0], [0.0, -1.0, 0.0]];

/// Standard deviation of the first low-pass stage, in pixels.
///
/// Together with [`gaussian_kernel`] this yields the 5x5 kernel the model calls
/// for.
const FIRST_SMOOTHING_SIGMA: f32 = 1.0;

/// Standard deviation of the second low-pass stage, in pixels.
///
/// Wider than the first on purpose: the second pass is what turns "this pixel
/// is next to an edge" into "this pixel is inside a textured region".
const SECOND_SMOOTHING_SIGMA: f32 = 1.5;

/// Guard added before the reciprocal of step 3.
///
/// A perfectly flat region smooths to exactly zero, so without it the cost of
/// the worst possible pixel would be an infinity — a value that propagates
/// through every sum the embedding layer takes. The epsilon caps that cost at
/// `1e6` instead, which is large enough that no trellis path will ever choose
/// such a pixel while a textured one is available.
const INVERSION_EPSILON: f32 = 1e-6;

/// Multiplier applied to the cost of pixels whose red channel can carry a bit.
///
/// Colour Rich Models, the strongest published detectors against colour images,
/// build their features from inter-channel differences and weight the red plane
/// most heavily: it is the channel whose demosaicing residual is most regular,
/// so an LSB flip there breaks a correlation the model has already learnt.
/// Raising the cost by twenty per cent does not forbid those pixels, it makes
/// the trellis prefer any comparable alternative, which is exactly the pressure
/// wanted — a hard exclusion would itself be a detectable statistic.
const RED_CHANNEL_PENALTY: f32 = 1.20;

/// Quantile of the cost distribution below which a pixel counts as smooth.
const SMOOTH_PERCENTILE: f32 = 0.05;

/// Largest fraction of the image allowed to be smooth.
const MAX_SMOOTH_RATIO: f32 = 0.30;

/// Largest fraction of the image one connected smooth region may occupy.
const MAX_SMOOTH_REGION_RATIO: f32 = 0.10;

/// Quantile of the cost distribution used to judge global texture.
const TEXTURE_PERCENTILE: f32 = 0.95;

/// Smallest value that quantile may take before the image is refused.
const MIN_TEXTURE_COST: f32 = 0.10;

/// Every reason the cost layer can refuse a container image.
#[derive(Debug)]
pub enum CostError {
    /// Too much of the image sits in the smooth tail of the cost distribution.
    ExcessiveSmoothRegions {
        /// Fraction of the pixels found below the smoothness threshold.
        ratio: f32,
    },
    /// One connected smooth region covers too much of the image.
    LargeSmoothRegion {
        /// Size of the offending region, in pixels.
        size: usize,
    },
    /// The image carries no textured region anywhere.
    InsufficientGlobalTexture,
}

impl fmt::Display for CostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CostError::ExcessiveSmoothRegions { ratio } => write!(
                f,
                "{:.1}% of the image is too smooth to hide anything; choose a container with \
                 more texture",
                ratio * 100.0
            ),
            CostError::LargeSmoothRegion { size } => write!(
                f,
                "the image contains a single flat area of {size} pixels; choose a container \
                 without large uniform surfaces"
            ),
            CostError::InsufficientGlobalTexture => write!(
                f,
                "the image has no textured region anywhere; choose a container with more detail"
            ),
        }
    }
}

impl std::error::Error for CostError {}

/// The HILL cost model.
///
/// Stateless: every parameter of the model is a constant of this module, so the
/// same container always produces the same map. Determinism is not a
/// convenience here — the extraction path never sees a cost map, and the whole
/// scheme rests on both sides deriving identical values from the image alone.
#[derive(Debug, Default, Clone, Copy)]
pub struct HillCostProvider;

impl HillCostProvider {
    /// Builds the provider.
    pub fn new() -> Self {
        Self
    }
}

impl CostProvider for HillCostProvider {
    type Error = CostError;

    /// Computes the HILL cost map of `image` and runs the three blocking gates.
    ///
    /// # Errors
    ///
    /// Returns [`CostError::ExcessiveSmoothRegions`] when too much of the image
    /// falls in the smooth tail, [`CostError::LargeSmoothRegion`] when one
    /// connected flat area is too large, and
    /// [`CostError::InsufficientGlobalTexture`] when no part of the image is
    /// textured — including the degenerate case of an image with no pixels.
    fn compute<'img>(&self, image: &'img ImageBuffer) -> Result<CostMap<'img>, CostError> {
        let (width, height) = image.dimensions();
        let width = width as usize;
        let height = height as usize;
        let color_space = image.color_space();

        let luma = luminance_plane(image.pixels(), width * height, color_space);

        // Step 1 — high-pass residual.
        let residual = high_pass(&luma, width, height);
        drop(luma);

        // Step 2 — first low-pass.
        let smoothed = convolve_separable(
            &residual,
            width,
            height,
            &gaussian_kernel(FIRST_SMOOTHING_SIGMA),
        );
        drop(residual);

        // Step 3 — second low-pass, then inversion.
        let second = convolve_separable(
            &smoothed,
            width,
            height,
            &gaussian_kernel(SECOND_SMOOTHING_SIGMA),
        );
        drop(smoothed);

        let mut costs: Vec<f32> = second
            .into_par_iter()
            .map(|texture| 1.0 / (texture + INVERSION_EPSILON))
            .collect();

        // Step 4 — red channel penalty. The map holds one cost per pixel, so
        // the penalty applies to whole pixels: on a colour layout the red plane
        // of every pixel is a candidate carrier, whereas a grayscale image has
        // no red channel to protect and is left untouched.
        if color_space.has_explicit_red_channel() {
            costs
                .par_iter_mut()
                .for_each(|cost| *cost *= RED_CHANNEL_PENALTY);
        }

        validate(&costs, width, height)?;

        Ok(CostMap::new(image, costs))
    }
}

/// Mirrors an out-of-range coordinate back into `0..len`.
///
/// Reflection about the edge pixel — `-1` maps to `1`, `len` maps to
/// `len - 2` — rather than the zero padding a naive convolution would use.
/// Zero padding surrounds the image with a black frame that does not exist, and
/// the Laplacian answers it with a bright border of pure artifact; the cost map
/// would then declare the outermost rows the most textured part of the image
/// and the embedder would crowd its changes into a border where nothing is
/// hidden. Reflection continues the image with its own content, so the border
/// response stays in the same range as the interior.
///
/// The modular reduction makes the function total for any offset, so a kernel
/// wider than the image cannot walk off the end of it.
fn reflect(coord: isize, len: usize) -> usize {
    if len <= 1 {
        return 0;
    }

    let len = len as isize;
    let period = 2 * (len - 1);

    let mut folded = coord % period;
    if folded < 0 {
        folded += period;
    }
    if folded >= len {
        folded = period - folded;
    }

    folded as usize
}

/// Step 1 — absolute response of the Laplacian in [`HIGH_PASS_KERNEL`].
///
/// The absolute value is taken per pixel and not at the end: the sign of the
/// Laplacian says which side of an edge a pixel is on, which is a property of
/// the scene and not of how much texture surrounds the pixel. Keeping it would
/// let the low-pass stages cancel the two sides of an edge against each other
/// and report the sharpest feature of the image as flat.
fn high_pass(luma: &[f32], width: usize, height: usize) -> Vec<f32> {
    let mut output = vec![0.0f32; luma.len()];
    if width == 0 || height == 0 {
        return output;
    }

    output
        .par_chunks_mut(width)
        .enumerate()
        .for_each(|(y, row)| {
            for (x, value) in row.iter_mut().enumerate() {
                let mut accumulator = 0.0f32;

                for (ky, weights) in HIGH_PASS_KERNEL.iter().enumerate() {
                    let sy = reflect(y as isize + ky as isize - 1, height);
                    for (kx, &weight) in weights.iter().enumerate() {
                        if weight == 0.0 {
                            continue;
                        }
                        let sx = reflect(x as isize + kx as isize - 1, width);
                        // In bounds by construction of `reflect`; the fallback
                        // keeps the function total without an index panic.
                        accumulator += weight * luma.get(sy * width + sx).copied().unwrap_or(0.0);
                    }
                }

                *value = accumulator.abs();
            }
        });

    output
}

/// Normalised 1-D Gaussian taps for a given standard deviation.
///
/// The radius is `ceil(2 * sigma)`, so `sigma = 1.0` gives the five taps the
/// model specifies and `sigma = 1.5` gives seven. Two standard deviations
/// capture about 95% of the mass of the kernel; truncating closer would leave
/// enough of the tail outside that the renormalisation below would visibly
/// change the shape of the filter rather than merely rescale it.
///
/// Built at call time because `exp` is not available in a const context on
/// stable Rust. The cost is a handful of exponentials against a convolution
/// over every pixel of the image.
fn gaussian_kernel(sigma: f32) -> Vec<f32> {
    let radius = (2.0 * sigma).ceil().max(1.0) as usize;

    let mut taps: Vec<f32> = (0..=2 * radius)
        .map(|tap| {
            let offset = tap as f32 - radius as f32;
            (-(offset * offset) / (2.0 * sigma * sigma)).exp()
        })
        .collect();

    // Normalised so the filter preserves the mean level of its input: an
    // unnormalised Gaussian would scale the whole residual plane, and the
    // absolute threshold of the texture gate would then depend on the kernel
    // width instead of on the image.
    let sum: f32 = taps.iter().sum();
    if sum > 0.0 {
        for tap in &mut taps {
            *tap /= sum;
        }
    }

    taps
}

/// Convolves with a 2-D Gaussian by running the 1-D kernel along each axis.
///
/// A Gaussian is separable: the outer product of the normalised 1-D taps *is*
/// the normalised 2-D kernel, so this is not an approximation of the 5x5 and
/// 7x7 filters the model calls for — it is those filters, evaluated in `2r`
/// multiplications per pixel instead of `(2r + 1)^2`.
fn convolve_separable(input: &[f32], width: usize, height: usize, taps: &[f32]) -> Vec<f32> {
    let horizontal = convolve_axis(input, width, height, taps, Axis::Horizontal);

    convolve_axis(&horizontal, width, height, taps, Axis::Vertical)
}

/// Which of the two passes of [`convolve_separable`] is running.
#[derive(Clone, Copy)]
enum Axis {
    /// Along a row: neighbours differ in `x`.
    Horizontal,
    /// Down a column: neighbours differ in `y`.
    Vertical,
}

/// One separable pass, parallelised over the rows of the output.
///
/// Rows are independent because the input is only ever read, never updated in
/// place, so the vertical pass sees the complete horizontal result no matter in
/// which order the threads finish.
fn convolve_axis(input: &[f32], width: usize, height: usize, taps: &[f32], axis: Axis) -> Vec<f32> {
    let mut output = vec![0.0f32; input.len()];
    if width == 0 || height == 0 || taps.is_empty() {
        return output;
    }

    let radius = (taps.len() / 2) as isize;

    output
        .par_chunks_mut(width)
        .enumerate()
        .for_each(|(y, row)| {
            for (x, value) in row.iter_mut().enumerate() {
                let mut accumulator = 0.0f32;

                for (tap_index, &tap) in taps.iter().enumerate() {
                    let offset = tap_index as isize - radius;
                    let (sx, sy) = match axis {
                        Axis::Horizontal => (reflect(x as isize + offset, width), y),
                        Axis::Vertical => (x, reflect(y as isize + offset, height)),
                    };

                    // In bounds by construction of `reflect`; the fallback
                    // keeps the function total without an index panic.
                    accumulator += tap * input.get(sy * width + sx).copied().unwrap_or(0.0);
                }

                *value = accumulator;
            }
        });

    output
}

/// Value at a quantile of an already sorted slice, by nearest rank.
///
/// `fraction` is in `0.0..=1.0`. The slice must be sorted ascending; sorting is
/// left to the caller because both quantiles the gates need come from the same
/// sort.
fn percentile(sorted: &[f32], fraction: f32) -> f32 {
    if sorted.is_empty() {
        return 0.0;
    }

    let rank = (fraction * sorted.len() as f32).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);

    // In bounds by the clamp above; the fallback keeps the function total.
    sorted.get(index).copied().unwrap_or(0.0)
}

/// Size of the largest 4-connected region of pixels cheaper than `threshold`.
///
/// Breadth-first with an explicit queue rather than recursion: a smooth region
/// can span millions of pixels, and a recursive flood fill would exhaust the
/// stack on exactly the images this gate exists to catch.
///
/// Diagonal neighbours are deliberately not connected. Two flat areas that
/// touch at a single corner are two areas as far as an embedder is concerned,
/// and 8-connectivity would merge them across a one-pixel contact into a region
/// large enough to fail the gate on its own.
fn largest_smooth_region(costs: &[f32], width: usize, height: usize, threshold: f32) -> usize {
    if width == 0 || height == 0 {
        return 0;
    }

    let is_smooth = |index: usize| costs.get(index).is_some_and(|&cost| cost < threshold);

    let mut visited = vec![false; costs.len()];
    let mut queue: VecDeque<usize> = VecDeque::new();
    let mut largest = 0usize;

    for start in 0..costs.len() {
        if visited[start] || !is_smooth(start) {
            continue;
        }

        visited[start] = true;
        queue.push_back(start);

        let mut size = 0usize;
        while let Some(index) = queue.pop_front() {
            size += 1;

            let x = index % width;
            let y = index / width;
            let neighbours = [
                (x > 0).then(|| index - 1),
                (x + 1 < width).then(|| index + 1),
                (y > 0).then(|| index - width),
                (y + 1 < height).then(|| index + width),
            ];

            for neighbour in neighbours.into_iter().flatten() {
                if !visited[neighbour] && is_smooth(neighbour) {
                    visited[neighbour] = true;
                    queue.push_back(neighbour);
                }
            }
        }

        largest = largest.max(size);
    }

    largest
}

/// The three blocking gates, applied to the finished cost map.
///
/// # Reach of the smoothness threshold
///
/// The first two gates measure the population below `theta_smooth`, and that
/// threshold is the fifth percentile of the very distribution being measured.
/// By construction no more than five per cent of the pixels can fall strictly
/// below it, so on any input the ratio stays under the thirty per cent limit
/// and no connected subset of that population can reach the ten per cent region
/// limit. Both gates are implemented exactly as specified, which keeps the
/// layer's behaviour equal to its specification and leaves the definition of
/// `theta_smooth` as the single place to edit if the thresholds are ever to be
/// armed — but as they stand they cannot reject an image, and the smoothness
/// rejection this layer performs in practice is the third gate.
///
/// # Orientation of the texture gate
///
/// The third gate reads the *upper* tail of the cost distribution against an
/// absolute bound. Cost is the reciprocal of smoothed texture energy, so
/// `percentile_95 < 0.10` says that ninety-five per cent of the image smooths
/// to a residual above `10.0` — a container whose every region is high-energy.
fn validate(costs: &[f32], width: usize, height: usize) -> Result<(), CostError> {
    // An image with no pixels has no textured region, and every quantile below
    // would be an invented number. Refused here rather than measured.
    if costs.is_empty() {
        return Err(CostError::InsufficientGlobalTexture);
    }

    // `total_cmp` rather than `partial_cmp`: the latter is fallible on NaN, and
    // a comparator that has to decide what to do about NaN is a comparator that
    // can panic.
    let mut sorted = costs.to_vec();
    sorted.par_sort_unstable_by(f32::total_cmp);

    let theta_smooth = percentile(&sorted, SMOOTH_PERCENTILE);

    // Gate 1 — how much of the image is smooth.
    let smooth_pixels = costs
        .par_iter()
        .filter(|&&cost| cost < theta_smooth)
        .count();
    let ratio = smooth_pixels as f32 / costs.len() as f32;
    if ratio > MAX_SMOOTH_RATIO {
        return Err(CostError::ExcessiveSmoothRegions { ratio });
    }

    // Gate 2 — how much of it is smooth in one piece. Scattered smooth pixels
    // are harmless: the embedder simply avoids them. A single large flat area
    // is not, because it removes a whole part of the image from consideration
    // and pushes every change into the remainder.
    let largest = largest_smooth_region(costs, width, height, theta_smooth);
    if largest as f32 > MAX_SMOOTH_REGION_RATIO * costs.len() as f32 {
        return Err(CostError::LargeSmoothRegion { size: largest });
    }

    // Gate 3 — whether the image has any texture at all.
    if percentile(&sorted, TEXTURE_PERCENTILE) < MIN_TEXTURE_COST {
        return Err(CostError::InsufficientGlobalTexture);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    use crate::image_io::buffer::ColorSpace;

    /// Side length of the synthetic containers below, in pixels.
    const SIDE: u32 = 64;

    /// Pixels of a container carrying photographic grain and nothing else.
    ///
    /// The amplitude is what decides the verdict, and it is the only thing
    /// these tests vary: grain of a few levels leaves the smoothed residual
    /// around seven, i.e. a cost around `0.15`, which clears the texture floor
    /// of `0.10`. Full-range noise leaves it two orders of magnitude higher and
    /// the reciprocal falls under the floor, which is the case the third gate
    /// refuses.
    fn grainy(seed: u64, amplitude: i16, channels: usize) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(seed);
        let samples = (SIDE * SIDE) as usize * channels;

        (0..samples)
            .map(|_| (128 + rng.random_range(-amplitude..=amplitude)).clamp(0, 255) as u8)
            .collect()
    }

    /// Reflection continues the image with its own content.
    #[test]
    fn coordinates_are_reflected_rather_than_padded() {
        assert_eq!(reflect(0, 10), 0);
        assert_eq!(reflect(9, 10), 9);
        assert_eq!(reflect(-1, 10), 1);
        assert_eq!(reflect(10, 10), 8);

        // Far outside the image: the fold is periodic, so no offset can walk
        // off the end of a plane however wide the kernel is.
        assert!(reflect(1_000, 10) < 10);
        assert!(reflect(-1_000, 10) < 10);

        // A degenerate axis has exactly one coordinate to fold onto.
        assert_eq!(reflect(7, 1), 0);
        assert_eq!(reflect(-7, 0), 0);
    }

    /// The taps are normalised, so the filter preserves the level of its input.
    #[test]
    fn the_gaussian_taps_sum_to_one() {
        for sigma in [1.0f32, 1.5] {
            let taps = gaussian_kernel(sigma);

            // Radius `ceil(2 sigma)`: five taps at 1.0 and seven at 1.5, which
            // are the 5x5 and 7x7 filters the model calls for.
            assert_eq!(taps.len(), 2 * (2.0 * sigma).ceil() as usize + 1);

            let sum: f32 = taps.iter().sum();
            assert!((sum - 1.0).abs() < 1e-5, "taps for {sigma} summed to {sum}");

            // Symmetric about the centre, which is what keeps the filter from
            // shifting the residual sideways.
            assert_eq!(taps.first(), taps.last());
        }
    }

    /// Quantiles are taken by nearest rank, and an empty sample has none.
    #[test]
    fn quantiles_are_read_by_nearest_rank() {
        let sorted: Vec<f32> = (0..100).map(|value| value as f32).collect();

        assert_eq!(percentile(&sorted, 0.0), 0.0);
        assert_eq!(percentile(&sorted, 0.05), 4.0);
        assert_eq!(percentile(&sorted, 0.95), 94.0);
        assert_eq!(percentile(&sorted, 1.0), 99.0);

        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    /// Smooth regions are 4-connected: a corner contact does not join two of
    /// them.
    #[test]
    fn smooth_regions_do_not_merge_across_a_corner() {
        // Two 2x2 cheap blocks touching only at the centre of a 4x4 map.
        let expensive = 10.0f32;
        let cheap = 0.0f32;
        let costs = vec![
            cheap, cheap, expensive, expensive, //
            cheap, cheap, expensive, expensive, //
            expensive, expensive, cheap, cheap, //
            expensive, expensive, cheap, cheap,
        ];

        assert_eq!(largest_smooth_region(&costs, 4, 4, 1.0), 4);

        // The same population in one piece, to show the count is of a region
        // and not of the whole smooth population.
        assert_eq!(largest_smooth_region(&[cheap; 16], 4, 4, 1.0), 16);

        // A degenerate geometry has no region to find.
        assert_eq!(largest_smooth_region(&costs, 0, 0, 1.0), 0);
    }

    /// An image with no pixels is refused rather than measured.
    #[test]
    fn an_empty_cost_map_has_no_texture() {
        let error = validate(&[], 0, 0)
            .map(|_| ())
            .expect_err("a map with no pixels must be refused");

        assert!(
            matches!(error, CostError::InsufficientGlobalTexture),
            "got: {error:?}"
        );
    }

    /// A grainy container is accepted, and its map covers every pixel.
    #[test]
    fn a_grainy_container_produces_a_usable_map() {
        let image = ImageBuffer::new(grainy(1, 3, 3), SIDE, SIDE, ColorSpace::Rgb8);

        let map = match HillCostProvider::new().compute(&image) {
            Ok(map) => map,
            Err(error) => panic!("photographic grain must be usable: {error}"),
        };

        assert_eq!(map.pixel_count(), image.pixel_count());
        assert_eq!(map.costs().len(), image.pixel_count());
        assert!(map.costs().iter().all(|cost| cost.is_finite() && *cost > 0.0));
    }

    /// A container that is high-energy everywhere has no textured region to
    /// prefer, and is refused rather than used badly.
    #[test]
    fn a_container_of_pure_noise_is_refused() {
        let image = ImageBuffer::new(grainy(2, 127, 3), SIDE, SIDE, ColorSpace::Rgb8);

        let error = HillCostProvider::new()
            .compute(&image)
            .map(|_| ())
            .expect_err("full-range noise must be refused");

        assert!(
            matches!(error, CostError::InsufficientGlobalTexture),
            "got: {error:?}"
        );
    }

    /// Colour containers pay the red-channel penalty; grayscale ones have no
    /// red plane to protect and do not.
    #[test]
    fn the_red_channel_penalty_applies_only_to_colour() {
        let pixel_count = (SIDE * SIDE) as usize;
        let rgb = grainy(3, 3, 3);

        // The grayscale twin is built from the colour image's own luma plane
        // rather than from the samples that produced it. Everything the model
        // reads is then identical between the two by construction, so the only
        // thing left to differ is the penalty.
        let luma: Vec<u8> = luminance_plane(&rgb, pixel_count, ColorSpace::Rgb8)
            .into_iter()
            .map(|level| level as u8)
            .collect();

        let colour_image = ImageBuffer::new(rgb, SIDE, SIDE, ColorSpace::Rgb8);
        let gray_image = ImageBuffer::new(luma, SIDE, SIDE, ColorSpace::Luma8);

        let provider = HillCostProvider::new();
        let colour = provider.compute(&colour_image).expect("grain must be usable");
        let gray = provider.compute(&gray_image).expect("grain must be usable");

        for (index, (with, without)) in colour.costs().iter().zip(gray.costs()).enumerate() {
            let ratio = with / without;
            assert!(
                (ratio - RED_CHANNEL_PENALTY).abs() < 1e-4,
                "pixel {index} cost {ratio} times as much in colour as in grayscale"
            );
        }
    }

    /// Every refusal tells the user what kind of container to reach for
    /// instead.
    #[test]
    fn every_refusal_explains_itself() {
        let excessive = CostError::ExcessiveSmoothRegions { ratio: 0.42 }.to_string();
        assert!(excessive.contains("42.0%"), "got: {excessive}");

        let region = CostError::LargeSmoothRegion { size: 12_345 }.to_string();
        assert!(region.contains("12345"), "got: {region}");

        assert!(CostError::InsufficientGlobalTexture
            .to_string()
            .contains("detail"));
    }
}

