//! Capacity sizer enforcing the `max_bpp` compile-time hard limit.
//!
//! The sizer answers one question before anything is encrypted or embedded: how
//! many payload bytes does this container actually admit? Asking it early is
//! what keeps the failure cheap and honest — a payload that does not fit is
//! rejected while it is still plaintext in the caller's hands, rather than after
//! a key derivation, a compression pass and a full cost analysis.
//!
//! # What the numbers mean
//!
//! Capacity is whittled down in three steps, and each one is a different kind of
//! constraint:
//!
//! 1. **The security ceiling.** Only [`MAX_BPP`] bits per usable position may be
//!    embedded. This is not a property of the image or of the code; it is the
//!    payload rate below which the modern rich-model detectors stay near chance.
//! 2. **The coding efficiency.** Syndrome-Trellis Codes do not reach the
//!    rate-distortion bound exactly, so a fraction of the gross bits is spent on
//!    the code itself. `STC_EFFICIENCY` is the conservative share that
//!    survives.
//! 3. **The cryptographic overhead.** The Poly1305 tag rides inside the embedded
//!    bits and is not payload, so it comes off the top.
//!
//! # Why the error says so little
//!
//! [`SizerError`] carries the exact figures for the caller that wants them, but
//! its message deliberately does not print them. A user-visible error is the one
//! artifact of this system an adversary is most likely to obtain — pasted into a
//! bug report, a chat, a screenshot — and a message quoting the exact available
//! byte count leaks the efficiency factor, the overhead and, through them, the
//! number of usable positions the container was found to have. The advice
//! "shorten the message or use a larger image" is everything the user needs and
//! nothing an attacker can key on.

use std::fmt;

use crate::cost::CostMap;
use crate::stego::stc::MAX_BPP;

/// Share of the gross capacity that survives Syndrome-Trellis coding.
///
/// The trellis spends part of the cover on the code itself, and the exact share
/// depends on the constraint height and on the shape of the cost distribution.
/// Eighty-five per cent is deliberately pessimistic: the sizer's promise is that
/// a payload it accepts will embed, so it must round against itself. Advertising
/// capacity the coder then refuses would turn a clean rejection into a failure
/// halfway through the pipeline.
const STC_EFFICIENCY: f32 = 0.85;

/// Bytes of Poly1305 tag carried inside the embedded bits.
const MAC_OVERHEAD_BYTES: usize = 16;

/// Bytes of ML-KEM-1024 ciphertext carried alongside an asymmetric payload.
///
/// The recipient decapsulates it to recover the message key, so it must travel
/// inside the container and comes out of the same budget as the payload.
#[cfg(feature = "pqc")]
const ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568;

/// Bits in a byte, named where the conversion happens.
const BITS_PER_BYTE: usize = 8;

/// The one way capacity planning can fail.
#[derive(Debug)]
pub enum SizerError {
    /// The payload is larger than the container admits.
    PayloadTooLarge {
        /// Size of the payload, in bytes.
        payload: usize,
        /// Bytes the container admits.
        available: usize,
        /// How many bytes over the limit the payload is.
        deficit: usize,
    },
}

impl fmt::Display for SizerError {
    /// Explains what to do, never what the limit is; see the module
    /// documentation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SizerError::PayloadTooLarge { .. } => write!(
                f,
                "the message does not fit in this image; shorten the message or use an image of \
                 higher resolution"
            ),
        }
    }
}

impl std::error::Error for SizerError {}

/// How the message key reaches the recipient.
///
/// The choice changes what has to be embedded besides the payload, which is why
/// capacity planning needs to know about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmbeddingMode {
    /// Both sides derive the key from a shared password. Nothing but the
    /// ciphertext and its tag is embedded.
    #[default]
    Symmetric,
    /// The message key is encapsulated to the recipient's ML-KEM-1024 public
    /// key, and the resulting ciphertext is embedded with the payload.
    #[cfg(feature = "pqc")]
    AsymmetricPqc,
}

impl EmbeddingMode {
    /// Bytes this mode spends on getting the key to the recipient.
    ///
    /// Zero for [`EmbeddingMode::Symmetric`], where the key never travels: the
    /// recipient rederives it from the password and the container itself.
    pub fn key_transport_overhead_bytes(self) -> usize {
        match self {
            EmbeddingMode::Symmetric => 0,
            #[cfg(feature = "pqc")]
            EmbeddingMode::AsymmetricPqc => ML_KEM_1024_CIPHERTEXT_BYTES,
        }
    }
}

/// What a container can carry, broken down by the constraint that shaped it.
///
/// The fields are `pub(crate)` and mirrored by accessors: the report is a
/// measurement, and nothing outside this layer should be able to write one that
/// no cost map produced.
#[derive(Debug, Clone, Copy)]
pub struct CapacityReport {
    /// Pixels in the container.
    pub(crate) total_pixels: usize,
    /// Pixels the embedder may use, i.e. those with a strictly positive cost.
    pub(crate) textured_pixels: usize,
    /// Bits allowed over the usable pixels by the [`MAX_BPP`] ceiling.
    pub(crate) gross_capacity_bits: usize,
    /// Bits left once Syndrome-Trellis coding has taken its share.
    pub(crate) net_capacity_bits: usize,
    /// Bytes of fixed cryptographic overhead: the Poly1305 tag.
    pub(crate) mac_overhead_bytes: usize,
    /// Bytes of payload the container admits.
    pub(crate) available_bytes: usize,
}

impl CapacityReport {
    /// Pixels in the container.
    pub fn total_pixels(&self) -> usize {
        self.total_pixels
    }

    /// Pixels the embedder may use.
    pub fn textured_pixels(&self) -> usize {
        self.textured_pixels
    }

    /// Bits allowed by the [`MAX_BPP`] ceiling, before coding overhead.
    pub fn gross_capacity_bits(&self) -> usize {
        self.gross_capacity_bits
    }

    /// Bits left once Syndrome-Trellis coding has taken its share.
    pub fn net_capacity_bits(&self) -> usize {
        self.net_capacity_bits
    }

    /// Bytes of fixed cryptographic overhead.
    pub fn mac_overhead_bytes(&self) -> usize {
        self.mac_overhead_bytes
    }

    /// Bytes of payload the container admits.
    pub fn available_bytes(&self) -> usize {
        self.available_bytes
    }
}

/// Measures what `cost_map` can carry in the given mode.
///
/// Total: every input produces a report. A container with no usable pixel is not
/// an error here, it is a report whose `available_bytes` is zero — deciding what
/// to do about that is [`validate_payload_fits`]'s job, and it needs a payload
/// size to say anything useful.
///
/// A position counts as usable when its cost is strictly positive. Zero is the
/// reserved value for "no embedder may touch this"; the HILL model never emits
/// it, since its costs are reciprocals of a non-negative quantity, so on a HILL
/// map every pixel counts and the ceiling is what binds.
pub fn compute_capacity(cost_map: &CostMap<'_>, mode: EmbeddingMode) -> CapacityReport {
    let total_pixels = cost_map.pixel_count();
    let textured_pixels = cost_map.costs().iter().filter(|&&cost| cost > 0.0).count();

    // In `f32`, matching `StcConfig::capacity_bits` exactly: the coder rejects a
    // payload the sizer accepted if the two disagree by even one bit, so both
    // sides compute the ceiling the same way rather than the most precise way.
    let gross_capacity_bits = (textured_pixels as f32 * MAX_BPP) as usize;
    let net_capacity_bits = (gross_capacity_bits as f32 * STC_EFFICIENCY) as usize;

    // Saturating throughout: a small container can owe more overhead than it has
    // capacity, and that is a container with no room for a payload — not a
    // subtraction that should wrap into an enormous one.
    let available_bytes = (net_capacity_bits / BITS_PER_BYTE)
        .saturating_sub(MAC_OVERHEAD_BYTES)
        .saturating_sub(mode.key_transport_overhead_bytes());

    CapacityReport {
        total_pixels,
        textured_pixels,
        gross_capacity_bits,
        net_capacity_bits,
        mac_overhead_bytes: MAC_OVERHEAD_BYTES,
        available_bytes,
    }
}

/// Checks a payload of `payload_len` bytes against a measured container.
///
/// # Errors
///
/// Returns [`SizerError::PayloadTooLarge`] when the payload exceeds
/// `report.available_bytes`, carrying the payload size, the available size and
/// the difference for callers that need to report progress towards a fit.
pub fn validate_payload_fits(
    payload_len: usize,
    report: &CapacityReport,
) -> Result<(), SizerError> {
    if payload_len > report.available_bytes {
        return Err(SizerError::PayloadTooLarge {
            payload: payload_len,
            available: report.available_bytes,
            deficit: payload_len - report.available_bytes,
        });
    }

    Ok(())
}
