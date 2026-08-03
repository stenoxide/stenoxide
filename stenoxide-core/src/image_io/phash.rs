//! Perceptual hash margin filter with a hard stability limit of `k <= 1`.
//!
//! The Argon2id salt is not stored anywhere. It is recomputed from the image
//! itself on both sides, which is what lets extraction work without any
//! metadata travelling next to the payload. That only holds if the hash the
//! receiver computes over the *stego* image is bit-for-bit the one the sender
//! computed over the *cover* image.
//!
//! Embedding perturbs the least significant bits of a few thousand pixels. A
//! 32x32 DCT coefficient is an average over the whole image, so those flips
//! move it by a vanishing amount — unless the coefficient happened to sit right
//! on the median, in which case an arbitrarily small perturbation flips its
//! bit and the salt, the master key and the whole payload are lost.
//!
//! This module therefore refuses to hash images whose coefficients sit too
//! close to the median. Each bit carries a margin, and:
//!
//! - `k == 0` unstable bits: the hash is reproducible, embedding proceeds.
//! - `k == 1`: the image is still usable, but the receiver has to try both
//!   values of the uncertain bit; [`recover_phash_salt`] does exactly that.
//! - `k >= 2`: rejected. Two uncertain bits would mean four hypotheses, each
//!   costing a full Argon2id derivation, and the number doubles from there.
//!
//! The margin filter also absorbs a second, subtler source of divergence: the
//! DCT is built on `cos`, which is not specified bit-exactly by IEEE 754 and
//! may differ in the last place between platforms. A bit whose margin exceeds
//! [`DELTA_MIN`] cannot be flipped by an error of that size.

use std::f32::consts::PI;
use std::fmt;

use image::{imageops, imageops::FilterType, GrayImage, Luma};
use sha3::{Digest, Sha3_256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::crypto::expand::{expand_master_key, DerivedKeys};
use crate::crypto::kdf::KeyDeriver;
use crate::image_io::buffer::{ColorSpace, CoverSource, ImageBuffer};

/// Side length of the square thumbnail the DCT is computed over.
const PHASH_THUMBNAIL_SIZE: usize = 32;

/// Number of AC coefficients turned into hash bits.
const N_HASH_BITS: usize = 64;

/// Smallest distance from the median a coefficient may have and still be
/// considered stable, in coefficient units.
///
/// The number is only meaningful against a fixed transform scale; see
/// [`dct_2d`], which is deliberately left unnormalised for that reason.
///
/// At that scale the threshold is a texture requirement in disguise. A smooth
/// container concentrates almost all of its energy in a handful of low
/// coefficients and leaves the rest piled up around a near-zero median, so
/// dozens of bits fall inside the margin and the image is rejected. A textured
/// one spreads its energy across the spectrum and clears the threshold on
/// every bit. That is the same property the cost layer wants, arrived at
/// independently.
const DELTA_MIN: f32 = 5.0;

/// Largest number of unstable bits an image may have and still be accepted.
///
/// One uncertain bit means two hypotheses on the receiving side. Two would
/// mean four Argon2id derivations, which at 128 MiB and four passes each is
/// already an unreasonable price to pay for a container the user can simply
/// replace.
const MAX_UNSTABLE_BITS: usize = 1;

/// Domain separator mixed into the salt so that the 64 hash bits cannot be
/// reused as an input to any other construction in this crate.
const PHASH_SALT_DOMAIN: &[u8] = b"STENOXIDE-v1-phash-salt";

/// Length of the derived salt, in bytes.
const PHASH_SALT_LEN: usize = 32;

/// Magic number of a Zstandard frame, little-endian, as it appears on the wire.
///
/// See [`prefix_matches_key`] for why a compression magic number, of all
/// things, is what distinguishes the two hypotheses.
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Number of keystream bytes XChaCha20-Poly1305 spends on the Poly1305 key
/// before it starts encrypting the message.
///
/// The AEAD construction of RFC 8439 reserves block zero for the one-time MAC
/// key and encrypts the plaintext from block one onwards, so a raw XChaCha20
/// instance has to be seeked past those 64 bytes to line its keystream up with
/// the ciphertext.
const AEAD_KEYSTREAM_OFFSET: u64 = 64;

/// Perceptual hash of the container image, used as the Argon2id salt.
///
/// The bytes are wiped when the value is dropped. Like [`MasterKey`], the type
/// implements neither [`Clone`], [`Copy`] nor [`Debug`]: the salt is not a
/// secret in the sense a key is, but it is a deterministic function of the
/// container, and leaking it into a log would let an attacker confirm which
/// image a given payload belongs to.
///
/// [`MasterKey`]: crate::crypto::kdf::MasterKey
#[derive(ZeroizeOnDrop)]
pub struct PHashSalt([u8; PHASH_SALT_LEN]);

impl PHashSalt {
    /// Wraps the 32 bytes of a perceptual hash as a salt.
    ///
    /// Restricted to the crate: outside code must obtain a salt through
    /// [`compute_stable_phash`], the only path that applies the stability
    /// filter.
    pub(crate) fn new(bytes: [u8; PHASH_SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the salt bytes, for use as the Argon2id salt.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Every way perceptual hashing can fail.
#[derive(Debug)]
pub enum PHashError {
    /// Too many coefficients sit within [`DELTA_MIN`] of the median for the
    /// hash to be reproducible after embedding.
    InsufficientStability {
        /// How many of the 64 bits are uncertain.
        unstable_bits: usize,
        /// The margin threshold that was applied.
        threshold: f32,
    },
    /// Neither hypothesis for the uncertain bit produced a key that matches the
    /// extracted payload. The image, the password or the payload is wrong.
    RecoveryFailed,
    /// Key derivation failed while testing a hypothesis.
    KdfError(String),
}

impl fmt::Display for PHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PHashError::InsufficientStability {
                unstable_bits,
                threshold,
            } => write!(
                f,
                "image is perceptually unstable: {unstable_bits} hash bits sit within {threshold} \
                 of the median; choose a container with more texture"
            ),
            PHashError::RecoveryFailed => write!(
                f,
                "could not recover the perceptual hash salt from the stego image"
            ),
            PHashError::KdfError(message) => {
                write!(f, "key derivation failed during salt recovery: {message}")
            }
        }
    }
}

impl std::error::Error for PHashError {}

/// The 64 hash bits together with how far each one is from the decision
/// boundary.
///
/// Kept as one value because the two arrays are always produced and consumed
/// together: a bit without its margin cannot be judged reproducible, and a
/// margin without its bit says nothing about the hash.
struct HashBits {
    /// `true` where the AC coefficient is above the median.
    bits: [bool; N_HASH_BITS],
    /// `|coefficient - median|` for each bit.
    margins: [f32; N_HASH_BITS],
}

impl HashBits {
    /// Indices of the bits whose margin is below [`DELTA_MIN`].
    fn unstable_indices(&self) -> Vec<usize> {
        self.margins
            .iter()
            .enumerate()
            .filter(|(_, &margin)| margin < DELTA_MIN)
            .map(|(index, _)| index)
            .collect()
    }
}

/// BT.601 luma of one pixel, from the raw sample bytes of that pixel.
///
/// `sample` is exactly one pixel as laid out by `color_space`, so every index
/// below is in bounds by construction: the callers slice the buffer with
/// [`ColorSpace::bytes_per_pixel`].
///
/// Shared with [`crate::image_io::jpeg_detect`], which measures its block
/// energies on the same luma plane. The two analyses must agree on what "the
/// brightness of a pixel" means, so there is exactly one implementation of it.
pub(super) fn luminance(sample: &[u8], color_space: ColorSpace) -> u8 {
    let (red, green, blue) = match color_space {
        // Grayscale is already luma; running it through the coefficients would
        // only add a rounding error.
        ColorSpace::Luma8 => return sample[0],
        ColorSpace::Rgb8 | ColorSpace::Rgba8 => {
            (sample[0] as f32, sample[1] as f32, sample[2] as f32)
        }
        // Samples were stored as explicit little-endian pairs by the validation
        // stage, so they are re-read the same way here rather than as native
        // `u16`. Normalised to [0, 255] before the coefficients are applied, so
        // that DELTA_MIN means the same thing at both bit depths.
        ColorSpace::Rgb16 => {
            const SCALE: f32 = 255.0 / 65535.0;
            let red = u16::from_le_bytes([sample[0], sample[1]]) as f32 * SCALE;
            let green = u16::from_le_bytes([sample[2], sample[3]]) as f32 * SCALE;
            let blue = u16::from_le_bytes([sample[4], sample[5]]) as f32 * SCALE;
            (red, green, blue)
        }
    };

    let luma = 0.299 * red + 0.587 * green + 0.114 * blue;
    luma.clamp(0.0, 255.0) as u8
}

/// Step 1 and 2 — converts the image to luma and resizes it to 32x32.
///
/// The resize is bilinear ([`FilterType::Triangle`]): the filter kernel is
/// scaled to the source resolution, so every input pixel contributes to the
/// thumbnail. That is what makes the result insensitive to the handful of
/// least significant bits embedding will flip.
fn luminance_thumbnail(img: &ImageBuffer) -> GrayImage {
    let (width, height) = img.dimensions();
    let color_space = img.color_space();
    let bytes_per_pixel = color_space.bytes_per_pixel();
    let pixels = img.pixels();

    let full = GrayImage::from_fn(width, height, |x, y| {
        let offset = img.pixel_offset(x, y);
        // In range for every coordinate the closure is called with, by the
        // `CoverSource` length contract. Falling back to black instead of
        // indexing keeps the function total.
        let sample = pixels.get(offset..offset + bytes_per_pixel);
        Luma([sample.map_or(0, |sample| luminance(sample, color_space))])
    });

    let side = PHASH_THUMBNAIL_SIZE as u32;
    imageops::resize(&full, side, side, FilterType::Triangle)
}

/// Step 3 — separable DCT-II of the 32x32 thumbnail.
///
/// Rows first, then columns; the output is row-major, and the receiver
/// reproduces exactly this order.
///
/// # Why the transform is left unnormalised
///
/// No orthonormal scale factor is applied, following the convention every
/// mainstream perceptual hash uses. The choice is not cosmetic: it fixes the
/// scale that [`DELTA_MIN`] is measured against. Orthonormalising would divide
/// every AC coefficient by about sixteen, and a threshold of `5.0` would then
/// reject even densely textured containers, which is the opposite of what the
/// filter is for. Only the ratio between the threshold and the transform scale
/// has any meaning; this function pins one half of it.
fn dct_2d(thumbnail: &GrayImage) -> [f32; PHASH_THUMBNAIL_SIZE * PHASH_THUMBNAIL_SIZE] {
    const N: usize = PHASH_THUMBNAIL_SIZE;

    // basis[k][n] = cos(pi/N * (n + 1/2) * k). Constant for a fixed N, but
    // rebuilt per call because `cos` is not available in a const context on
    // stable Rust.
    let mut basis = [[0.0f32; N]; N];
    for (k, row) in basis.iter_mut().enumerate() {
        for (n, value) in row.iter_mut().enumerate() {
            *value = (PI / N as f32 * (n as f32 + 0.5) * k as f32).cos();
        }
    }

    let mut rows = [0.0f32; N * N];
    for y in 0..N {
        for (k, basis_row) in basis.iter().enumerate() {
            let mut acc = 0.0f32;
            for (n, weight) in basis_row.iter().enumerate() {
                acc += thumbnail.get_pixel(n as u32, y as u32).0[0] as f32 * weight;
            }
            rows[y * N + k] = acc;
        }
    }

    let mut coefficients = [0.0f32; N * N];
    for x in 0..N {
        for (k, basis_row) in basis.iter().enumerate() {
            let mut acc = 0.0f32;
            for (n, weight) in basis_row.iter().enumerate() {
                acc += rows[n * N + x] * weight;
            }
            coefficients[k * N + x] = acc;
        }
    }

    coefficients
}

/// Median of the 64 AC coefficients.
///
/// An even number of samples, so the two central values are averaged. Sorted
/// with [`f32::total_cmp`] rather than `partial_cmp`: the latter is fallible on
/// NaN, and a comparator that has to decide what to do about NaN is a
/// comparator that can panic.
fn median(coefficients: &[f32; N_HASH_BITS]) -> f32 {
    let mut sorted = *coefficients;
    sorted.sort_by(f32::total_cmp);
    (sorted[N_HASH_BITS / 2 - 1] + sorted[N_HASH_BITS / 2]) / 2.0
}

/// Steps 1 to 4 — everything up to, but not including, the stability verdict.
///
/// Split out because [`recover_phash_salt`] needs the margins as well as the
/// bits, and recomputing a DCT over a multi-megapixel image to get them back
/// would be wasteful.
fn compute_hash_bits(img: &ImageBuffer) -> HashBits {
    let thumbnail = luminance_thumbnail(img);
    let coefficients = dct_2d(&thumbnail);

    // The DC term at [0, 0] is the mean brightness of the whole image. It
    // carries no structure, dwarfs every other coefficient and would drag the
    // median with it, so it is dropped and the next 64 coefficients are taken
    // in row-major order.
    let mut ac = [0.0f32; N_HASH_BITS];
    ac.copy_from_slice(&coefficients[1..=N_HASH_BITS]);

    let median = median(&ac);

    let mut bits = [false; N_HASH_BITS];
    let mut margins = [0.0f32; N_HASH_BITS];
    for index in 0..N_HASH_BITS {
        bits[index] = ac[index] > median;
        margins[index] = (ac[index] - median).abs();
    }

    HashBits { bits, margins }
}

/// Step 6 — packs the 64 bits and hashes them into a salt.
///
/// Bits are packed most-significant-first inside each byte: bit `i` of the hash
/// lands in bit `7 - (i % 8)` of byte `i / 8`. The order is arbitrary but it is
/// part of the wire format, so both sides must agree on it.
fn salt_from_bits(bits: &[bool; N_HASH_BITS]) -> PHashSalt {
    let mut packed = [0u8; N_HASH_BITS / 8];
    for (index, &bit) in bits.iter().enumerate() {
        if bit {
            packed[index / 8] |= 1 << (7 - (index % 8));
        }
    }

    let mut hasher = Sha3_256::new();
    hasher.update(packed);
    hasher.update(PHASH_SALT_DOMAIN);
    let digest: [u8; PHASH_SALT_LEN] = hasher.finalize().into();

    PHashSalt::new(digest)
}

/// Every salt a container's perceptual hash could have produced.
///
/// One when the hash is fully determined; two when a single coefficient sits
/// inside the margin, in which case the sender used one of the pair and nothing
/// in the image says which.
pub(crate) struct PHashHypotheses {
    /// Salt of the bits exactly as they measure on this image.
    ///
    /// The one the sender used whenever the image is the unmodified cover, and
    /// the overwhelmingly likely one even for a stego image: the uncertain
    /// coefficient only moves if embedding happened to push it across the
    /// median.
    pub(crate) primary: PHashSalt,
    /// Salt of the same bits with the uncertain one flipped, when there is one.
    pub(crate) alternative: Option<PHashSalt>,
}

/// Enumerates the salts a container's hash can take, applying the same
/// stability limit as [`compute_stable_phash`].
///
/// The extraction path needs this rather than a single salt. Its problem is
/// circular: the payload is what tells the two hypotheses apart, and reading the
/// payload needs the permutation seed, which is derived from the salt. It can
/// only be broken by trying a hypothesis, extracting under it and letting
/// [`recover_phash_salt`] judge the result — which requires being able to name
/// the other hypothesis, and that is what this function provides.
///
/// # Errors
///
/// Returns [`PHashError::InsufficientStability`] when more than
/// [`MAX_UNSTABLE_BITS`] coefficients sit within [`DELTA_MIN`] of the median.
pub(crate) fn phash_salt_hypotheses(img: &ImageBuffer) -> Result<PHashHypotheses, PHashError> {
    let hash = compute_hash_bits(img);
    let unstable = hash.unstable_indices();

    if unstable.len() > MAX_UNSTABLE_BITS {
        return Err(PHashError::InsufficientStability {
            unstable_bits: unstable.len(),
            threshold: DELTA_MIN,
        });
    }

    let alternative = unstable.first().map(|&index| {
        let mut flipped = hash.bits;
        // In bounds: the indices come from enumerating the margin array, which
        // has exactly as many entries as the bit array. The fallback keeps the
        // function total without an index panic.
        if let Some(bit) = flipped.get_mut(index) {
            *bit = !*bit;
        }

        salt_from_bits(&flipped)
    });

    Ok(PHashHypotheses {
        primary: salt_from_bits(&hash.bits),
        alternative,
    })
}

/// Computes the perceptual hash salt of a container image, refusing images
/// whose hash would not survive embedding.
///
/// Public so that the stability of a container can be asked about on its own,
/// without running an embedding. The returned salt is opaque outside this
/// crate — it has no public accessor — so exposing this function grants the
/// verdict and not the value.
///
/// # Errors
///
/// Returns [`PHashError::InsufficientStability`] when more than
/// [`MAX_UNSTABLE_BITS`] coefficients sit within [`DELTA_MIN`] of the median.
/// Note that a single unstable bit is *accepted* here: the sender does not
/// care which value it takes, because the receiver resolves the ambiguity
/// during extraction.
pub fn compute_stable_phash(img: &ImageBuffer) -> Result<PHashSalt, PHashError> {
    Ok(phash_salt_hypotheses(img)?.primary)
}

/// Tests whether `ciphertext_prefix` was produced under the keys derived from a
/// candidate salt.
///
/// # Why this is not a MAC check
///
/// Poly1305 authenticates the ciphertext as a whole and its tag lives at the
/// very end of it, so a 64-byte prefix carries nothing that can be verified.
/// Extracting the entire payload before the salt is known is not an option
/// either: the STC decoder needs the permutation seed, which is derived from
/// the very key we are trying to pin down.
///
/// What a prefix *does* allow is decrypting it with the raw XChaCha20
/// keystream and looking at the plaintext. The payload is Zstandard-compressed
/// before it is encrypted, so the correct key uncovers a Zstandard frame magic
/// number and a wrong key uncovers uniformly random bytes — a discriminator
/// that is wrong with probability `2^-32`.
///
/// That is sound because this function decides nothing security-relevant. It
/// only picks which of two hypotheses to try first; the actual authentication
/// still happens when the pipeline decrypts the full payload under the chosen
/// salt, and a mistake here surfaces there as an ordinary authentication
/// failure.
fn prefix_matches_key(keys: &DerivedKeys, ciphertext_prefix: &[u8]) -> bool {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use chacha20::XChaCha20;

    let Some(head) = ciphertext_prefix.get(..ZSTD_FRAME_MAGIC.len()) else {
        return false;
    };

    let mut cipher = XChaCha20::new(keys.enc_key().into(), keys.nonce().into());
    if cipher.try_seek(AEAD_KEYSTREAM_OFFSET).is_err() {
        return false;
    }

    let mut plaintext = Zeroizing::new(head.to_vec());
    if cipher.apply_keystream_b2b(head, &mut plaintext).is_err() {
        return false;
    }

    plaintext.as_slice() == ZSTD_FRAME_MAGIC
}

/// Derives the keys for one hypothesis and checks them against the payload.
///
/// Returns `Ok(Some(salt))` when the hypothesis matches, `Ok(None)` when it
/// does not, and `Err` only when key derivation itself failed — a condition
/// that says nothing about which hypothesis was right and must not be confused
/// with a rejection.
fn try_hypothesis(
    bits: &[bool; N_HASH_BITS],
    password: &[u8],
    kdf: &impl KeyDeriver,
    ciphertext_prefix: &[u8],
) -> Result<Option<PHashSalt>, PHashError> {
    let salt = salt_from_bits(bits);

    let master_key = kdf
        .derive(password, &salt)
        .map_err(|err| PHashError::KdfError(err.to_string()))?;
    let keys =
        expand_master_key(&master_key).map_err(|err| PHashError::KdfError(err.to_string()))?;
    // Wiped here rather than at the end of the scope: nothing below needs it,
    // and the two hypotheses run concurrently, so one of the two master keys is
    // always live material that no longer has any use.
    drop(master_key);

    let matched = prefix_matches_key(&keys, ciphertext_prefix);
    drop(keys);

    if matched {
        Ok(Some(salt))
    } else {
        Ok(None)
    }
}

/// Recovers the salt of a stego image whose hash has one uncertain bit.
///
/// `ciphertext_prefix` is the first 64 bytes of the provisionally extracted
/// payload. It is used to tell the two hypotheses apart; see
/// [`prefix_matches_key`] for what "tell apart" means here and why it is not,
/// and does not need to be, an authentication step.
///
/// # Errors
///
/// Returns [`PHashError::InsufficientStability`] if the stego image has more
/// than [`MAX_UNSTABLE_BITS`] uncertain bits, [`PHashError::RecoveryFailed`] if
/// neither hypothesis matches the payload, and [`PHashError::KdfError`] if the
/// key derivation used to test a hypothesis failed.
pub(crate) fn recover_phash_salt(
    stego_img: &ImageBuffer,
    password: &[u8],
    kdf: &impl KeyDeriver,
    ciphertext_prefix: &[u8],
) -> Result<PHashSalt, PHashError> {
    let hash = compute_hash_bits(stego_img);
    let unstable = hash.unstable_indices();

    let uncertain = match unstable.as_slice() {
        // k = 0: every coefficient is far enough from the median that
        // embedding cannot have moved it across. The hash the receiver just
        // computed is the one the sender used, and no search is needed. This
        // is exactly what `compute_stable_phash` would return, minus a second
        // pass over the image.
        [] => return Ok(salt_from_bits(&hash.bits)),
        [index] => *index,
        more => {
            return Err(PHashError::InsufficientStability {
                unstable_bits: more.len(),
                threshold: DELTA_MIN,
            })
        }
    };

    let mut cleared = hash.bits;
    cleared[uncertain] = false;
    let mut set = hash.bits;
    set[uncertain] = true;

    // Argon2id at the production parameters costs 128 MiB and several hundred
    // milliseconds. Running the two hypotheses on separate threads makes the
    // recovery cost the same wall time as an ordinary derivation, at the price
    // of holding two memory blocks at once.
    let (cleared, set) = rayon::join(
        || try_hypothesis(&cleared, password, kdf, ciphertext_prefix),
        || try_hypothesis(&set, password, kdf, ciphertext_prefix),
    );

    // Both hypotheses can only match if the discriminator collided, which is a
    // `2^-32` event; picking either one is then as good as picking the other,
    // and the full-payload authentication downstream catches the mistake.
    match (cleared?, set?) {
        (Some(salt), _) | (None, Some(salt)) => Ok(salt),
        (None, None) => Err(PHashError::RecoveryFailed),
    }
}
