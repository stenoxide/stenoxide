//! The properties an embedding has to keep, measured on a real cover/stego
//! pair.
//!
//! # What this file is for
//!
//! The coverage floor proves that the embedding code runs. It says nothing
//! about the only thing this program exists to do. A change to the HILL cost
//! map, to the rate ceiling, to the permutation or to the operator that moves a
//! sample can leave every other test in this workspace green while making the
//! container trivially detectable — the round trip still recovers the message,
//! the capacity arithmetic still adds up, and the payload is now sitting in the
//! flat regions of the image with its least significant bits overwritten.
//!
//! The tests below are the gate against that. They build one cover/stego pair
//! and interrogate it five ways.
//!
//! # What it is not
//!
//! Not a proof of undetectability. That needs a trained detector — SRNet, YeNet
//! or SRM with an FLD ensemble — a corpus of natural covers, and enough samples
//! that the estimation error at `0.02` bpp lands below the effect being
//! measured. That is a manual experiment on a machine with a GPU, not something
//! a merge gate can run in a minute.
//!
//! What these tests do catch is the coarse regression: an embedder that stopped
//! consulting the cost map, a rate ceiling that stopped binding, a `±1`
//! operator that turned back into plain LSB replacement. Each of those is a
//! silent, total loss of the property the design is built around, and each one
//! shows up here immediately.
//!
//! # Determinism
//!
//! Every input is seeded. The cover comes from a fixed seed through
//! [`test_support::write_stable_cover`], the payload from a fixed seed through
//! [`test_support::incompressible_payload`], the control images from fixed
//! seeds of their own, and the password is a constant. There is no sampling
//! anywhere: each statistic is computed over every pixel of the container. A
//! gate that fails once in twenty runs gets switched off, and a switched-off
//! gate protects nothing, so every threshold below is stated with enough
//! margin that the measured figure would have to move by a large factor to
//! reach it — and each one records the figure it was set against.
//!
//! # Cost
//!
//! Building the pair is the whole expense: a cover, its HILL map, an embedding,
//! and the stego image read back. Every test shares one pair through a
//! [`OnceLock`], so the pipeline runs once per binary however many of them are
//! selected. The statistics themselves are linear passes over four million
//! pixels and cost nothing beside it.
//!
//! The cover is built here rather than taken from the fixture cache the other
//! integration binaries share: that cache also holds a second cover and a
//! JPEG-laundered container, neither of which this file reads, and generating
//! them is a large fraction of the runtime of a gate that has to stay cheap
//! enough to run on every pull request.

#![cfg(not(debug_assertions))]

use std::sync::OnceLock;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::crypto::aead::XChaCha20Poly1305Cipher;
use stenoxide_core::crypto::kdf::Argon2Kdf;
use stenoxide_core::image_io::buffer::CoverSource;
use stenoxide_core::image_io::validate::load_and_validate;
use stenoxide_core::pipeline::{EmbedPipeline, EmbedReport};
use stenoxide_core::stego::sizer::{compute_capacity, EmbeddingMode};
use stenoxide_core::stego::stc::MAX_BPP;
use stenoxide_core::test_support;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

/// The password the embedding below uses.
const PASSWORD: &[u8] = "invariant-gate-passphrase".as_bytes();

/// Seed the cover is searched from.
///
/// The same one the other integration binaries build their primary fixture
/// from, and it is a good seed rather than an arbitrary one: it passes the
/// perceptual-stability gate on its first candidate, so the search inside
/// `stable_cover` costs one image rather than several.
const COVER_SEED: u64 = 337;

/// Share of the measured capacity the payload fills, in per cent.
///
/// The change rate is what most of these tests measure, so the container is
/// loaded close to the ceiling rather than lightly: a near-empty container
/// would pass every threshold here by embedding almost nothing. Ninety per cent
/// leaves room for the Zstandard frame header and the Poly1305 tag, which are
/// charged against the same budget and are not known until the payload has been
/// compressed.
const PAYLOAD_FILL_PERCENT: usize = 90;

/// Seed of the control image that replaces every carrier bit.
const FULL_REPLACEMENT_SEED: u64 = 0x4C53_425F_4655_4C4C;

/// Share of the pixels the saturated control rewrites, in per cent.
///
/// Every one of them: the chi-square test only speaks at rates approaching the
/// capacity of the container, so the control it is calibrated against is the
/// worst case rather than a plausible payload.
const FULL_REPLACEMENT_PERCENT: u64 = 100;

/// Seed of the control image that replaces a tenth of the carrier bits.
const SPARSE_REPLACEMENT_SEED: u64 = 0x4C53_425F_5350_4152;

/// Share of the pixels the sparse control rewrites, in per cent.
///
/// Five times the rate ceiling of this crate. Chosen so the control is a
/// payload a detector should have no trouble with, without being so large that
/// it only demonstrates the estimator works in the trivial case.
const SPARSE_REPLACEMENT_PERCENT: u64 = 10;

/// One cover, the stego image made from it, and the cost map that steered it.
struct EmbeddingPair {
    /// Raw samples of the cover, row-major.
    cover: Vec<u8>,
    /// Raw samples of the stego image, in the same layout.
    stego: Vec<u8>,
    /// HILL cost of every pixel of the cover, row-major.
    costs: Vec<f32>,
    /// Bytes per pixel of both images.
    bytes_per_pixel: usize,
    /// Width of both images, in pixels.
    width: usize,
    /// Pixels in each image.
    pixel_count: usize,
    /// What the pipeline reported about the embedding.
    report: EmbedReport,
}

impl EmbeddingPair {
    /// Byte offsets at which the two images differ.
    fn changed_samples(&self) -> Vec<usize> {
        self.cover
            .iter()
            .zip(self.stego.iter())
            .enumerate()
            .filter(|(_, (cover, stego))| cover != stego)
            .map(|(offset, _)| offset)
            .collect()
    }

    /// The carrier sample of every pixel of an image of this geometry.
    ///
    /// The first byte of each pixel; see the pipeline's frame module for why
    /// that is the carrier on every supported layout.
    fn carrier_plane(&self, samples: &[u8]) -> Vec<u8> {
        samples
            .iter()
            .step_by(self.bytes_per_pixel)
            .copied()
            .collect()
    }
}

/// The pair every test below reads, built once per test binary.
fn pair() -> &'static EmbeddingPair {
    static PAIR: OnceLock<EmbeddingPair> = OnceLock::new();

    PAIR.get_or_init(build_pair)
}

/// Embeds a near-capacity payload into the shared cover and measures both ends.
///
/// The pipeline is production-grade in everything except its key deriver, for
/// the reason the other suites give: Argon2id at production parameters costs
/// four hundred milliseconds and buys this file nothing, since none of the
/// statistics below depend on how the key was stretched.
fn build_pair() -> EmbeddingPair {
    let cover_file = NamedTempFile::new().expect("temporary cover file");
    let cover_path = cover_file.path().to_path_buf();
    test_support::write_stable_cover(&cover_path, COVER_SEED);

    let cover_image = load_and_validate(&cover_path).expect("the cover must load");

    let (width, height) = cover_image.dimensions();
    let bytes_per_pixel = cover_image.color_space().bytes_per_pixel();
    let pixel_count = cover_image.pixel_count();
    let cover = cover_image.pixels().to_vec();

    // The same map the pipeline will compute for itself. Taken here because a
    // cost map borrows its image and the pipeline's copy never leaves it.
    let cost_map = HillCostProvider::new()
        .compute(&cover_image)
        .expect("the cover must be usable");
    let capacity = compute_capacity(&cost_map, EmbeddingMode::Symmetric);
    let costs = cost_map.costs().to_vec();
    drop(cost_map);

    let payload_len = capacity.available_bytes() * PAYLOAD_FILL_PERCENT / 100;
    let stego_file = NamedTempFile::new().expect("temporary stego file");

    let report = EmbedPipeline::new(
        Argon2Kdf::low_cost_for_tests(),
        XChaCha20Poly1305Cipher::new(),
        HillCostProvider::new(),
    )
    .embed(
        &cover_path,
        Zeroizing::new(test_support::incompressible_payload(payload_len)),
        Zeroizing::new(PASSWORD.to_vec()),
        stego_file.path(),
    )
    .expect("a payload inside the measured capacity must embed");

    // Read back through the validator rather than from the buffer in memory:
    // what a steganalyst sees is the file, and a container this crate could not
    // load again would be a defect of its own.
    let stego_image = load_and_validate(stego_file.path()).expect("the stego image must load");
    assert_eq!(
        stego_image.dimensions(),
        (width, height),
        "embedding must not change the geometry of the container"
    );

    EmbeddingPair {
        cover,
        stego: stego_image.pixels().to_vec(),
        costs,
        bytes_per_pixel,
        width: width as usize,
        pixel_count,
        report,
    }
}

/// INVARIANT 1 — every altered sample moved by exactly one level, and none of
/// them saturated.
///
/// Correctness rather than statistics, and the one test here whose failure
/// makes the rest meaningless: a sample that moved by more than a level is a
/// visible artifact, and a `0` that became `255` is a wrap that both destroys
/// the payload and leaves a black pixel where a white one was. Nothing but the
/// carrier byte of a pixel may differ at all.
#[test]
fn every_change_moves_one_sample_by_one_level() {
    let pair = pair();

    for (offset, (&cover, &stego)) in pair.cover.iter().zip(pair.stego.iter()).enumerate() {
        if cover == stego {
            continue;
        }

        assert_eq!(
            offset % pair.bytes_per_pixel,
            0,
            "sample {offset} is not a carrier byte and must not have changed"
        );

        let delta = i16::from(stego) - i16::from(cover);
        assert!(
            delta == 1 || delta == -1,
            "sample {offset} moved from {cover} to {stego}"
        );

        // Stated separately from the `±1` bound above even though it follows
        // from it. The two failures are different defects — a wide change is a
        // broken operator, a wrapped one is a `u8` overflow in the coder — and
        // an assertion that names the second is worth the line.
        if cover == 0 {
            assert_eq!(stego, 1, "a sample at 0 must go up, not wrap");
        }
        if cover == u8::MAX {
            assert_eq!(stego, 254, "a sample at 255 must come down, not wrap");
        }
    }
}

/// INVARIANT 2 — the effective change rate stays under the ceiling.
///
/// Measured against the samples that actually differ, not against the bits the
/// embedding layer believed it was writing. The two are not the same number:
/// the trellis spends fewer changes than bits, and it is the changes a detector
/// counts. A rate ceiling that stopped binding — a raised `MAX_BPP`, a sizer
/// that stopped charging the frame, a coder ignoring its capacity check — shows
/// up here as a rate above the constant.
#[test]
fn the_change_rate_stays_under_the_ceiling() {
    let pair = pair();
    let changed = pair.changed_samples().len();

    let change_rate = changed as f32 / pair.pixel_count as f32;
    assert!(
        change_rate <= MAX_BPP,
        "{changed} samples changed over {} pixels, a rate of {change_rate} against a ceiling of \
         {MAX_BPP}",
        pair.pixel_count
    );

    // The pipeline's own accounting has to agree with the image on both counts:
    // the rate it reports is bits embedded per pixel, which bounds the changes,
    // and the number of modified positions it reports is the number of samples
    // that differ.
    assert!(
        pair.report.effective_bpp <= MAX_BPP,
        "the pipeline reported {} bits per pixel",
        pair.report.effective_bpp
    );
    assert_eq!(
        pair.report.pixels_modified, changed,
        "the pipeline reported {} modified positions and the image shows {changed}",
        pair.report.pixels_modified
    );
}

/// INVARIANT 3 — the changes land where the cost map is cheap.
///
/// The most valuable test in this file. Everything else here would still pass
/// if the embedder picked its positions at random: the changes would still be
/// `±1`, still be few, and still barely move a histogram. What would be gone is
/// the entire reason the HILL map is computed — and with it the property that
/// keeps a rich-model detector near chance.
///
/// Formulated as a quantile rather than as an absolute cost, so it does not
/// depend on the scale of the map: almost every change must fall in the cheaper
/// half of the cost distribution. Random placement would put half of them
/// there.
#[test]
fn changes_land_where_the_cost_map_is_cheap() {
    let pair = pair();

    let mut sorted = pair.costs.clone();
    sorted.sort_by(f32::total_cmp);
    let median = sorted[sorted.len() / 2];

    let changed = pair.changed_samples();
    assert!(
        !changed.is_empty(),
        "the embedding changed nothing, so there is no placement to judge"
    );

    let cheap = changed
        .iter()
        .filter(|&&offset| pair.costs[offset / pair.bytes_per_pixel] < median)
        .count();

    let share = cheap as f32 / changed.len() as f32;
    assert!(
        share >= CHEAP_HALF_SHARE,
        "only {share} of the {} changes fell in the cheaper half of the cost map",
        changed.len()
    );
}

/// Smallest share of the changes that must fall in the cheaper half of the cost
/// map.
///
/// Measured at `0.877` on the fixture pair, against the `0.5` random placement
/// would give. The threshold sits between the two and nearer the floor: the
/// trellis is entitled to spend an expensive position now and then to satisfy a
/// syndrome, and the share it settles on depends on the cost distribution of
/// the cover, so a threshold hugging the measurement would fail the day the
/// fixture seed moved. What must never happen is the share drifting towards
/// what a coder ignoring the map would produce, and three quarters is far below
/// anything such a coder could reach.
const CHEAP_HALF_SHARE: f32 = 0.75;

/// INVARIANT 4a — the pair-of-values chi-square does not flag the container.
///
/// The classical Westfeld-Pfitzmann test. LSB *replacement* pairs every even
/// value with the odd one above it and moves population between them until the
/// two are equal, which collapses this statistic towards its degrees of
/// freedom. The `±1` operator this crate uses does no such thing: it moves a
/// sample away from the end of the range it sits at, in a direction taken from
/// the keystream, so the pair populations stay where the cover put them.
///
/// The test is stated as a comparison against the cover rather than against a
/// critical value, because the cover's own statistic is large and a p-value
/// computed against it would say more about the fixture than about the
/// embedding. The control image is what shows the instrument is live: the same
/// cover with every carrier bit replaced has to be flagged.
#[test]
fn the_pair_of_values_test_does_not_flag_the_container() {
    let pair = pair();

    let cover = pov_chi_square(&histogram(&pair.carrier_plane(&pair.cover)));
    let stego = pov_chi_square(&histogram(&pair.carrier_plane(&pair.stego)));
    let replaced = pov_chi_square(&histogram(&pair.carrier_plane(&lsb_replaced(
        pair,
        FULL_REPLACEMENT_PERCENT,
        FULL_REPLACEMENT_SEED,
    ))));

    assert!(
        stego >= cover * CHI_SQUARE_RETENTION,
        "the statistic fell from {cover} on the cover to {stego} on the stego image"
    );

    // The control. Without it a chi-square implementation that always returned
    // a large number would pass the assertion above for ever.
    assert!(
        replaced < cover * CHI_SQUARE_RETENTION,
        "full replacement left the statistic at {replaced} against {cover} on the cover, so this \
         test cannot detect it"
    );
}

/// Share of the cover's chi-square statistic the stego image must retain.
///
/// The fixture pair retains `0.9996` of it — `88_719` against `88_752` — and
/// the same cover with every carrier bit replaced retains `0.0007`, a statistic
/// of `58`. Three orders of magnitude separate the two outcomes, so the
/// threshold can sit anywhere between them; a tenth of the cover's statistic is
/// far enough below the measurement to absorb a different cover and far enough
/// above the control to fail on a return to LSB replacement.
const CHI_SQUARE_RETENTION: f64 = 0.9;

/// INVARIANT 4b — sample pair analysis estimates no payload.
///
/// The estimator of Dumitrescu, Wu and Wang: it reads the population of pairs
/// of adjacent samples that LSB replacement moves between trace subsets, and
/// solves for the replacement rate that would explain what it sees. It is
/// sensitive at rates far below what the chi-square test can reach, which is
/// what makes it the right instrument here.
///
/// Two assertions, and both are needed. The estimate on the stego image must
/// stay near the estimate on the cover — the cover's own figure is not zero,
/// because no natural or synthetic image satisfies the estimator's model
/// exactly — and the sparse control must be estimated near the rate it was
/// actually written at, which is what proves the estimator is measuring
/// anything at all.
#[test]
fn sample_pair_analysis_estimates_no_payload() {
    let pair = pair();

    let cover = sample_pair_estimate(&pair.carrier_plane(&pair.cover), pair.width);
    let stego = sample_pair_estimate(&pair.carrier_plane(&pair.stego), pair.width);
    let control = sample_pair_estimate(
        &pair.carrier_plane(&lsb_replaced(
            pair,
            SPARSE_REPLACEMENT_PERCENT,
            SPARSE_REPLACEMENT_SEED,
        )),
        pair.width,
    );

    assert!(
        (stego - cover).abs() <= SPA_DRIFT,
        "the estimate moved from {cover} on the cover to {stego} on the stego image"
    );

    // The control, at five times the rate ceiling. The estimator has to see it,
    // or the assertion above is measuring nothing.
    assert!(
        control - cover > SPA_DRIFT,
        "replacing {SPARSE_REPLACEMENT_PERCENT}% of the carrier bits moved the estimate from \
         {cover} to {control}, so this test cannot detect it"
    );
}

/// Largest drift in the sample-pair estimate that embedding may cause.
///
/// The fixture pair moves the estimate by `0.0008` — from `-0.0059` on the
/// cover to `-0.0068` on the stego image — while replacing a tenth of the
/// carrier bits moves it by `0.100`. The threshold is an order of magnitude
/// above the first and an order of magnitude below the second.
const SPA_DRIFT: f64 = 0.01;

/// INVARIANT 5 — the histogram of the carrier plane barely moves.
///
/// The weakest of the five and the cheapest: the total variation distance
/// between the two histograms is bounded by twice the change count whatever the
/// embedder does, so this cannot fail while invariant 2 holds. What it adds is
/// the *shape* of the drift — a bound per bin rather than in total, which a
/// change count alone does not give. An embedder that put all of its changes
/// into one narrow band of values would satisfy invariant 2 and fail here.
#[test]
fn the_histogram_barely_moves() {
    let pair = pair();

    let cover = histogram(&pair.carrier_plane(&pair.cover));
    let stego = histogram(&pair.carrier_plane(&pair.stego));

    let drift: u64 = cover
        .iter()
        .zip(stego.iter())
        .map(|(cover, stego)| cover.abs_diff(*stego))
        .sum();
    let total_drift = drift as f64 / pair.pixel_count as f64;
    assert!(
        total_drift <= HISTOGRAM_DRIFT,
        "the histogram moved by {total_drift} of the container"
    );

    // Per bin, against the population of that bin. Empty bins are skipped: a
    // value the cover never took has no share for a change to be measured
    // against, and the absolute count that lands there is bounded by the change
    // count already.
    for (level, (&cover_count, &stego_count)) in cover.iter().zip(stego.iter()).enumerate() {
        if cover_count < HISTOGRAM_BIN_FLOOR {
            continue;
        }

        let share = cover_count.abs_diff(stego_count) as f64 / cover_count as f64;
        assert!(
            share <= HISTOGRAM_BIN_DRIFT,
            "the population of level {level} moved by {share} of itself"
        );
    }
}

/// Largest share of the container the histogram may move by, in total
/// variation.
///
/// Measured at `0.0003` on the fixture pair. The ceiling is not arbitrary: no
/// embedding can move more than two counts per changed sample, so invariant 2
/// caps this quantity at `2 * MAX_BPP`, i.e. `0.04`. A quarter of that leaves
/// the assertion room to fail on a container where the changes were unusually
/// concentrated while staying two orders of magnitude above the measurement.
const HISTOGRAM_DRIFT: f64 = 0.01;

/// Smallest population a histogram bin needs before its drift is measured.
///
/// A bin holding a handful of pixels moves by a large share of itself when a
/// single change lands in it, which says nothing about the embedding. One
/// thousand pixels out of four million is small enough to keep every level the
/// cover actually uses in the measurement.
const HISTOGRAM_BIN_FLOOR: u64 = 1_000;

/// Largest share of its own population one histogram bin may move by.
///
/// The worst bin of the fixture pair moves by `0.005`. Ten times that: the
/// figure depends on how the cover's levels are distributed, and a threshold
/// set against one histogram would not survive a different cover.
const HISTOGRAM_BIN_DRIFT: f64 = 0.05;

/// The 256-bin histogram of a plane of samples.
fn histogram(plane: &[u8]) -> [u64; 256] {
    let mut counts = [0u64; 256];

    for &sample in plane {
        counts[sample as usize] += 1;
    }

    counts
}

/// The pair-of-values chi-square statistic of a histogram.
///
/// One term per pair `(2k, 2k+1)`, taken against the mean of the two: under LSB
/// replacement at full rate the two populations converge on that mean, so the
/// statistic collapses. Pairs whose expected count is too small to be worth a
/// chi-square term are skipped, as the test's usual formulation demands.
fn pov_chi_square(histogram: &[u64; 256]) -> f64 {
    let mut statistic = 0.0;

    for pair in histogram.chunks_exact(2) {
        let (even, odd) = (pair[0] as f64, pair[1] as f64);
        let expected = (even + odd) / 2.0;

        if expected < MIN_EXPECTED_COUNT {
            continue;
        }

        statistic += (even - expected).powi(2) / expected;
    }

    statistic
}

/// Smallest expected count a chi-square term is taken over.
///
/// Five is the classical rule of thumb: below it the chi-square approximation
/// to the multinomial stops holding and the term contributes noise.
const MIN_EXPECTED_COUNT: f64 = 5.0;

/// The sample-pair estimate of the LSB replacement rate of a plane.
///
/// Pairs are horizontally adjacent samples, taken disjointly along each row.
/// The quadratic below is the one derived by Dumitrescu, Wu and Wang: its
/// smaller root is the share of samples whose least significant bit was
/// overwritten. A cover carries an estimate of its own, which is why every
/// assertion above reads the difference between two of these rather than the
/// figure itself.
fn sample_pair_estimate(plane: &[u8], width: usize) -> f64 {
    let (mut x, mut y, mut z, mut w, mut total) = (0u64, 0u64, 0u64, 0u64, 0u64);

    for row in plane.chunks_exact(width) {
        for pair in row.chunks_exact(2) {
            let (first, second) = (pair[0], pair[1]);
            total += 1;

            if first == second {
                z += 1;
            } else if first / 2 == second / 2 {
                w += 1;
            }

            let even = second % 2 == 0;
            if (even && first < second) || (!even && first > second) {
                x += 1;
            } else if (even && first > second) || (!even && first < second) {
                y += 1;
            }
        }
    }

    let (x, y, z, w, total) = (x as f64, y as f64, z as f64, w as f64, total as f64);

    let a = 0.5 * (w + z);
    let b = 2.0 * x - total;
    let c = y - x;

    // A degenerate quadratic is a plane with no pair the estimator can read.
    // Solved linearly rather than divided by zero.
    if a.abs() < f64::EPSILON {
        return if b.abs() < f64::EPSILON { 0.0 } else { -c / b };
    }

    let discriminant = b * b - 4.0 * a * c;
    if discriminant < 0.0 {
        return 0.0;
    }

    let root = discriminant.sqrt();
    let first = (-b + root) / (2.0 * a);
    let second = (-b - root) / (2.0 * a);

    // The smaller root, as the derivation specifies.
    first.min(second)
}

/// The cover with the carrier bit of `percent` of its pixels overwritten by a
/// keystream bit.
///
/// Plain LSB replacement, which is the regression every statistical test in
/// this file exists to catch, and the control each of them is calibrated
/// against. Nothing but the carrier byte is touched, so the control differs
/// from the stego image in how the bits were written and in nothing else.
fn lsb_replaced(pair: &EmbeddingPair, percent: u64, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut samples = pair.cover.clone();

    for sample in samples.iter_mut().step_by(pair.bytes_per_pixel) {
        if rng.random_range(0..100) >= percent {
            continue;
        }

        *sample = (*sample & !1) | u8::from(rng.random_bool(0.5));
    }

    samples
}
