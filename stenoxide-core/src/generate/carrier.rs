//! Drawing one sample of the cover distribution, conditioned on the bit it has
//! to carry.
//!
//! # Why rejection sampling and not an overwrite
//!
//! The obvious construction is to draw a sample and then set its least
//! significant bit to the carrier bit. It is also exactly what destroys the one
//! property this mode exists for. Overwriting redistributes mass within each
//! pair of values `(2k, 2k+1)`: every sample that landed on the wrong side of
//! the pair is moved to the other, which flattens the natural imbalance of the
//! histogram a detector can measure. Applied at the same load factor and
//! measured against the `pair_ratio` statistic, an overwrite moves the value by
//! hundreds of pooled standard deviations on a two-peaked texture and by some
//! fifteen on a texture like this one, whose levels are spread across the
//! range. The conditioned draw does not move it at all.
//!
//! Rejection sampling is exact. The accepted samples are distributed as the
//! cover restricted to one parity class, and because the two classes carry
//! equal mass, mixing them over a uniform carrier bit reproduces the
//! unconditioned distribution itself:
//!
//! ```text
//! sum over b of  P(sample = v | LSB = b) P(b)  =  P(sample = v)
//! ```
//!
//! So the container that carries a message and the container that carries
//! nothing are draws from one distribution. There are not two hypotheses for a
//! detector to separate.
//!
//! The equality holds as long as the least significant bit of the
//! unconditioned distribution is a fair coin, which is what
//! [`GRAIN_SIGMA`](super::texture::GRAIN_SIGMA) is chosen for.
//!
//! # Why the loop is bounded
//!
//! Each draw accepts with probability one half, so two are needed on average
//! and the loop terminates with probability one. That is not the same as
//! terminating: a base level pressed against the clamp could make one parity
//! unreachable, and the loop would then spin forever. The texture keeps every
//! base level twelve standard deviations clear of both ends, so the bound is
//! never approached — but it is there, and reaching it is an error rather than
//! a panic, because a library that can abort a caller's process has no business
//! being linked into one.

use rand::rngs::StdRng;
use rand::Rng;

use std::f32::consts::TAU;
use std::fmt;

use super::texture::GRAIN_SIGMA;

/// Draws one conditioned sample may take before the attempt is abandoned.
///
/// Each iteration accepts with probability one half, so reaching sixty-four is
/// a `2^-64` event for any base level the texture can produce. It is a guard
/// against a level that should not exist, not a tuning parameter.
const MAX_DRAWS: usize = 64;

/// The one way conditioned sampling can fail.
///
/// A distinct type rather than a variant of the caller's error enum: it says
/// something specific about the texture — that a base level ended up against
/// the end of the range — and the caller is what decides how to report it. It
/// is re-exported by [`crate::generate`], which is where a caller meets it.
#[derive(Debug)]
pub struct RejectionExhausted;

impl fmt::Display for RejectionExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "conditioned sampling did not converge in {MAX_DRAWS} draws; a base level of the \
             texture sits against the end of the range"
        )
    }
}

impl std::error::Error for RejectionExhausted {}

/// One sample of the cover distribution, unconstrained.
///
/// The distribution every claim in this module is about: `floor(base + N(0,
/// sigma))`, clamped to the representable range.
pub(crate) fn draw_free(rng: &mut StdRng, base: f32) -> u8 {
    (base + gaussian(rng, GRAIN_SIGMA)).clamp(0.0, 255.0) as u8
}

/// One sample of the cover distribution, conditioned on its least significant
/// bit being `bit`.
///
/// # Errors
///
/// Returns [`RejectionExhausted`] when [`MAX_DRAWS`] draws all landed on the
/// wrong parity, which cannot happen for a base level this crate's texture
/// produces; see the module documentation.
pub(crate) fn draw_with_lsb(
    rng: &mut StdRng,
    base: f32,
    bit: u8,
) -> Result<u8, RejectionExhausted> {
    for _ in 0..MAX_DRAWS {
        let value = draw_free(rng, base);
        if value & 1 == bit & 1 {
            return Ok(value);
        }
    }

    Err(RejectionExhausted)
}

/// One normally distributed sample of standard deviation `sigma`, by
/// Box-Muller.
///
/// Only the cosine half of the transform is kept and the sine half discarded.
/// Storing the spare would make the function stateful, and the number of draws
/// this makes per sample is not fixed — it is what the rejection loop decides —
/// so a carried-over value would tie one sample's grain to the parity of the
/// one before it.
fn gaussian(rng: &mut StdRng, sigma: f32) -> f32 {
    // Bounded away from zero: `ln(0)` is negative infinity, and a single
    // infinite grain sample would clamp to a black or white pixel.
    let uniform = unit(rng).max(f32::EPSILON);
    let angle = unit(rng) * TAU;

    sigma * (-2.0 * uniform.ln()).sqrt() * angle.cos()
}

/// A uniform draw in `[0, 1)`, taken straight from the generator.
///
/// Twenty-four bits, which is the resolution of an `f32` mantissa: any more
/// would only produce values that round to the same float. Written out rather
/// than taken from the range sampler because this is called some fifty million
/// times per container, and the general form spends a rejection loop and a
/// widening conversion on a question that is answered here by a shift.
fn unit(rng: &mut StdRng) -> f32 {
    (rng.next_u32() >> 8) as f32 / 16_777_216.0
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use rand::SeedableRng;

    /// A base level in the middle of the range, where the texture keeps them.
    const BASE: f32 = 128.0;

    /// Samples each statistical assertion below is made over.
    const SAMPLES: usize = 20_000;

    /// A generator seeded for reproducibility rather than for secrecy.
    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    /// The conditioned draw returns the parity it was asked for, every time.
    #[test]
    fn a_conditioned_sample_carries_the_bit_it_was_given() {
        let mut rng = rng(11);

        for index in 0..SAMPLES {
            let bit = (index % 2) as u8;
            match draw_with_lsb(&mut rng, BASE, bit) {
                Ok(sample) => assert_eq!(sample & 1, bit),
                Err(error) => panic!("a mid-range level must converge: {error}"),
            }
        }
    }

    /// Conditioning does not move the distribution.
    ///
    /// The claim the mode rests on, checked the only way a test can check it:
    /// a stream of samples conditioned on alternating bits has the same mean
    /// and spread as a stream drawn freely. A construction that overwrote the
    /// bit instead would pass the mean and fail the histogram, so the pairing
    /// is asserted as well.
    #[test]
    fn conditioning_reproduces_the_unconditioned_distribution() {
        let mut free_rng = rng(101);
        let mut conditioned_rng = rng(202);

        let free: Vec<u8> = (0..SAMPLES)
            .map(|_| draw_free(&mut free_rng, BASE))
            .collect();
        let conditioned: Vec<u8> = (0..SAMPLES)
            .map(|index| {
                draw_with_lsb(&mut conditioned_rng, BASE, (index % 2) as u8)
                    .expect("a mid-range level must converge")
            })
            .collect();

        let mean = |samples: &[u8]| {
            samples.iter().map(|&sample| sample as f64).sum::<f64>() / samples.len() as f64
        };

        // The standard error of the mean at this sample count is about
        // `sigma / sqrt(n)` = 0.014 levels, so a tenth of a level is seven
        // standard errors and still far below anything conditioning could do.
        assert!(
            (mean(&free) - mean(&conditioned)).abs() < 0.1,
            "free {} against conditioned {}",
            mean(&free),
            mean(&conditioned)
        );

        // The histogram, pair by pair. Overwriting the bit would empty one half
        // of every pair into the other; a conditioned draw leaves the pair
        // populated as the cover distribution populates it.
        let count = |samples: &[u8], value: u8| {
            samples.iter().filter(|&&sample| sample == value).count()
        };
        for value in 120..=136u8 {
            let free_count = count(&free, value) as f64;
            let conditioned_count = count(&conditioned, value) as f64;
            let spread = (free_count + conditioned_count).sqrt().max(1.0);

            assert!(
                (free_count - conditioned_count).abs() < 6.0 * spread,
                "value {value}: free {free_count} against conditioned {conditioned_count}"
            );
        }
    }

    /// The free draw stays inside the representable range.
    #[test]
    fn a_free_sample_is_clamped_to_the_range() {
        let mut rng = rng(7);

        for base in [0.0f32, 4.0, 128.0, 251.0, 255.0] {
            for _ in 0..1_000 {
                // The type is `u8`, so the assertion is that the clamp happened
                // rather than that the conversion wrapped: a level of `-3.0`
                // cast directly would be `0` and one of `300.0` would saturate,
                // and neither is something to leave to a cast.
                let _sample = draw_free(&mut rng, base);
            }
        }
    }

    /// A base level against the end of the range is reported, not spun on.
    ///
    /// The texture never produces one — that is checked in
    /// [`super::super::texture`] — so this is the only place the guard can be
    /// exercised at all.
    #[test]
    fn an_unreachable_parity_is_an_error_rather_than_a_hang() {
        let mut rng = rng(3);

        // At a base of `-1000` every draw clamps to zero, so an odd sample is
        // unreachable and the loop must give up.
        let error = draw_with_lsb(&mut rng, -1_000.0, 1)
            .map(|_| ())
            .expect_err("an unreachable parity must be reported");

        assert!(error.to_string().contains("did not converge"));
        assert!(draw_with_lsb(&mut rng, -1_000.0, 0).is_ok());
    }
}
