//! Fisher-Yates permutation of embedding positions, seeded by the STC key.
//!
//! # Why the positions are permuted at all
//!
//! Embedding in raster order concentrates every change in the first rows of the
//! image that happen to be cheap, which is a spatial signature a steganalyst can
//! read off a residual plot without any statistics at all. Visiting the pixels
//! in a secret order spreads the changes over the whole container, and — more
//! importantly — makes the set of touched positions unpredictable to anyone who
//! does not hold the key.
//!
//! # Why a stream cipher rather than an RNG
//!
//! The permutation must be reproduced exactly by the extraction path, which sees
//! nothing but the stego image and the password. A general purpose RNG gives no
//! guarantee that two builds, two platforms or two versions of a crate produce
//! the same stream; ChaCha20 is specified bit by bit, so the same seed yields
//! the same keystream everywhere and forever. Determinism here is a correctness
//! requirement, not a convenience: a single differing draw permutes the tail of
//! the sequence and the payload is lost.
//!
//! # Why rejection sampling
//!
//! Reducing a uniform 64-bit draw with `value % bound` is biased whenever
//! `bound` does not divide the size of the draw space: the low residues occur
//! once more often than the high ones. The bias is tiny per swap, but it applies
//! to every position of a multi-megapixel image and it is *structured* — it
//! favours the same residues for everyone, which is precisely the kind of
//! regularity an attacker can accumulate over many images. Draws landing in the
//! incomplete final block are discarded instead, leaving an exactly uniform
//! index at the price of a repeat that happens with probability below
//! `bound / 2^64`.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use zeroize::ZeroizeOnDrop;

/// Nonce of the keystream that drives the shuffle.
///
/// Fixed at zero on purpose. A nonce exists to keep two messages encrypted
/// under the same key apart, and there is only ever one "message" per key here:
/// the single keystream consumed by one shuffle. Uniqueness is already provided
/// by the seed, which HKDF derives per container from a master key that is
/// itself salted with the image's perceptual hash.
const PERMUTATION_NONCE: [u8; 12] = [0u8; 12];

/// Bytes of keystream produced per refill.
///
/// Drawing eight bytes at a time straight from the cipher would call into it
/// once per swap — tens of millions of times on a large container. A buffer of
/// whole ChaCha20 blocks amortises that to one call per 64 blocks. The size is a
/// whole multiple of [`DRAW_BYTES`], which is what lets [`KeystreamReader`]
/// assume a draw never straddles the end of the buffer.
const KEYSTREAM_BUFFER_BYTES: usize = 4096;

/// Bytes consumed by one draw: a `u64` read little-endian.
const DRAW_BYTES: usize = 8;

/// Buffered reader over the ChaCha20 keystream of one permutation.
///
/// Wiped on drop: the keystream is a direct function of the STC seed, so a copy
/// of it left in freed memory is as good as a copy of the seed for anyone who
/// wants to reconstruct the embedding order.
#[derive(ZeroizeOnDrop)]
struct KeystreamReader {
    /// The cipher itself. Skipped by the derive because it does not implement
    /// `Zeroize`; the `zeroize` feature of the `chacha20` crate — enabled in the
    /// workspace manifest — already makes it wipe its own state on drop.
    #[zeroize(skip)]
    cipher: ChaCha20,
    /// Keystream bytes produced by the last refill.
    buffer: [u8; KEYSTREAM_BUFFER_BYTES],
    /// Offset of the next unread byte in [`KeystreamReader::buffer`].
    cursor: usize,
}

impl KeystreamReader {
    /// Starts a keystream under `seed` and [`PERMUTATION_NONCE`].
    ///
    /// The cursor starts past the end of the buffer so that the first draw
    /// refills it rather than returning the zeros it was constructed with.
    fn new(seed: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20::new(Key::from_slice(seed), Nonce::from_slice(&PERMUTATION_NONCE)),
            buffer: [0u8; KEYSTREAM_BUFFER_BYTES],
            cursor: KEYSTREAM_BUFFER_BYTES,
        }
    }

    /// The next eight keystream bytes, interpreted as a little-endian `u64`.
    fn next_u64(&mut self) -> u64 {
        if self.cursor + DRAW_BYTES > self.buffer.len() {
            self.refill();
        }

        let mut word = [0u8; DRAW_BYTES];

        // In bounds by the refill above, because the buffer length is a whole
        // multiple of `DRAW_BYTES`. The fallback keeps the function total
        // without an index panic; it cannot be reached.
        if let Some(bytes) = self.buffer.get(self.cursor..self.cursor + DRAW_BYTES) {
            word.copy_from_slice(bytes);
            self.cursor += DRAW_BYTES;
        }

        u64::from_le_bytes(word)
    }

    /// Advances the cipher by one buffer's worth of keystream.
    ///
    /// The buffer is cleared first because `apply_keystream` XORs into its
    /// argument: XOR against zero is the keystream itself, XOR against the
    /// previous contents would be noise.
    fn refill(&mut self) {
        self.buffer = [0u8; KEYSTREAM_BUFFER_BYTES];
        self.cipher.apply_keystream(&mut self.buffer);
        self.cursor = 0;
    }
}

/// Builds the secret visiting order of `n_pixels` embedding positions.
///
/// The result is a permutation of `0..n_pixels`: every index appears exactly
/// once, so the caller can walk it end to end and touch each position at most
/// once. The same `stc_seed` and the same `n_pixels` always produce the same
/// permutation, on every platform and every build — the extraction path depends
/// on it.
///
/// # Algorithm
///
/// Fisher-Yates, walking down from the last index. At step `i` the draw is an
/// unbiased index into `0..=i`, obtained by rejection sampling over the
/// keystream as described in the module documentation.
pub(crate) fn generate_pixel_permutation(n_pixels: usize, stc_seed: &[u8; 32]) -> Vec<usize> {
    let mut permutation: Vec<usize> = (0..n_pixels).collect();

    // Nothing to shuffle, and no keystream is consumed: the identity is the
    // only permutation of zero or one element.
    if n_pixels < 2 {
        return permutation;
    }

    let mut keystream = KeystreamReader::new(stc_seed);

    for index in (1..n_pixels).rev() {
        let bound = index as u64 + 1;

        // Largest multiple of `bound` that fits in the draw space. Values at or
        // above it belong to the incomplete final block and are discarded, so
        // every accepted draw comes from a range that `bound` divides exactly.
        let ceiling = u64::MAX - u64::MAX % bound;

        let draw = loop {
            let value = keystream.next_u64();
            if value < ceiling {
                break value;
            }
        };

        // In range by construction: the modulus is at most `index`, and `index`
        // is a valid position of a vector of `n_pixels` elements.
        permutation.swap(index, (draw % bound) as usize);
    }

    permutation
}
