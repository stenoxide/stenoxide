//! Raw bindings to the external libsdc++ Syndrome-Trellis Codes library.
//!
//! This is the only module in the crate where `unsafe` is permitted. Every
//! `unsafe` block added here must carry a `// SAFETY:` comment justifying why
//! it upholds the invariants of the foreign function it calls.
//!
//! # Assumed library
//!
//! The declarations below follow the reference C++ implementation of
//! Syndrome-Trellis Codes published by the DDE Lab of Binghamton University,
//! **libsdc++ version 1.1** (the release that ships `stc_embed_c.h`,
//! `stc_extract_c.h`, `stc_ml_c.h` and `common.h`). Three properties of that
//! release are assumed throughout and are what the `// SAFETY:` comments rest
//! on:
//!
//! 1. The entry points are exported with C linkage. The sources are C++, so the
//!    build must expose them through the `extern "C"` declarations of the
//!    shipped headers; a build that mangles these symbols fails at link time,
//!    which is the failure mode we want — never a silent mismatch.
//! 2. Neither entry point retains any pointer it is handed. Both consume their
//!    inputs within the call, so the borrows below are valid for exactly as long
//!    as the call lasts.
//! 3. Neither entry point lets a C++ exception escape. The library signals
//!    failure through its return value; an exception unwinding across the FFI
//!    boundary would be undefined behaviour, and no amount of Rust-side
//!    checking can catch it.
//!
//! # Vector conventions
//!
//! The library works on *binary* vectors with one symbol per byte: every
//! element of the cover, stego and message arrays is `0` or `1`, never a packed
//! byte. The payload crossing this module's safe surface is packed, so the
//! wrappers unpack it on the way in and repack it on the way out; see
//! [`unpack_bits`] and [`pack_bits`].

#![allow(unsafe_code)]

use std::fmt;

use zeroize::ZeroizeOnDrop;

#[cfg(feature = "ffi-stc")]
use std::os::raw::{c_uchar, c_uint, c_void};
#[cfg(feature = "ffi-stc")]
use zeroize::Zeroizing;

/// Bits per pixel the embedder may never exceed.
///
/// A hard limit of the design, not a tunable: detection accuracy against the
/// modern rich-model detectors climbs steeply with payload rate, and everything
/// this crate does — the HILL costs, the trellis, the permutation — buys
/// invisibility only in the low-rate regime. Exposing this as a runtime
/// parameter would let a caller trade away, in one argument, the property the
/// whole system exists to provide.
pub const MAX_BPP: f32 = 0.02;

/// Constraint height of the trellis used unless a caller overrides it.
///
/// The library's own default. Embedding efficiency grows with the height and so
/// does the cost of the Viterbi pass, which is `O(2^h)` per position; ten is the
/// value the published measurements use to sit near the rate-distortion bound
/// without becoming impractical.
pub const DEFAULT_TRELLIS_HEIGHT: u32 = 10;

/// Every way the Syndrome-Trellis Codes layer can refuse to run.
#[derive(Debug)]
pub enum StcError {
    /// The cover vector and the cost vector describe different position counts.
    LengthMismatch {
        /// Number of cover positions supplied.
        pixels: usize,
        /// Number of costs supplied.
        costs: usize,
    },
    /// The payload asks for more bits than `max_bpp` allows over this cover.
    PayloadExceedsCapacity {
        /// Bits the payload needs.
        payload_bits: usize,
        /// Bits the cover may carry under the `max_bpp` hard limit.
        capacity_bits: usize,
    },
    /// A cost was negative, infinite or not a number.
    InvalidCostMap,
    /// The foreign library reported a failure.
    FfiError(String),
    /// The crate was built without the `ffi-stc` feature.
    FeatureNotEnabled,
}

impl fmt::Display for StcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StcError::LengthMismatch { pixels, costs } => write!(
                f,
                "cover and cost vectors disagree: {pixels} positions against {costs} costs"
            ),
            StcError::PayloadExceedsCapacity {
                payload_bits,
                capacity_bits,
            } => write!(
                f,
                "payload of {payload_bits} bits exceeds the {capacity_bits} bits this cover may \
                 carry"
            ),
            StcError::InvalidCostMap => write!(
                f,
                "the cost map contains a negative or non-finite value and cannot be used"
            ),
            StcError::FfiError(message) => write!(f, "the stc coder failed: {message}"),
            StcError::FeatureNotEnabled => write!(
                f,
                "syndrome-trellis coding is unavailable: this build was made without the \
                 \"ffi-stc\" feature"
            ),
        }
    }
}

impl std::error::Error for StcError {}

/// Parameters of one Syndrome-Trellis Codes operation.
///
/// Holds key material — the permutation seed — and is therefore wiped on drop.
/// Encode and decode must be given identical configurations: the trellis height
/// is part of the code definition, so a decode at a different height reads a
/// different syndrome and recovers nothing.
#[derive(ZeroizeOnDrop)]
pub struct StcConfig {
    /// Seed of the embedding permutation, derived by HKDF from the master key.
    pub(crate) stc_seed: [u8; 32],
    /// Constraint height of the trellis.
    pub(crate) trellis_height: u32,
    /// Bits per pixel ceiling. Always [`MAX_BPP`]; see the constant.
    pub(crate) max_bpp: f32,
}

impl StcConfig {
    /// Builds a configuration around `stc_seed`, with the defaults of this
    /// crate.
    ///
    /// There is no constructor that takes a `max_bpp`. The field exists so the
    /// limit can be read, not chosen.
    pub fn new(stc_seed: [u8; 32]) -> Self {
        Self {
            stc_seed,
            trellis_height: DEFAULT_TRELLIS_HEIGHT,
            max_bpp: MAX_BPP,
        }
    }

    /// Borrows the permutation seed.
    pub fn stc_seed(&self) -> &[u8; 32] {
        &self.stc_seed
    }

    /// Constraint height of the trellis.
    pub fn trellis_height(&self) -> u32 {
        self.trellis_height
    }

    /// The bits-per-pixel ceiling in force. Always [`MAX_BPP`].
    pub fn max_bpp(&self) -> f32 {
        self.max_bpp
    }

    /// Bits `positions` cover elements may carry under the ceiling.
    ///
    /// Truncating towards zero, so the limit is never rounded up into a payload
    /// that the ceiling does not actually allow. The arithmetic is done in
    /// `f32` deliberately: [`crate::stego::sizer`] advertises capacity with the
    /// same expression, and a wider intermediate type here would let a payload
    /// pass the sizer and then fail this check.
    pub fn capacity_bits(&self, positions: usize) -> usize {
        (positions as f32 * self.max_bpp) as usize
    }
}

impl fmt::Debug for StcConfig {
    /// Prints the parameters of the configuration, never the seed.
    ///
    /// Written by hand rather than derived: a derived implementation would put
    /// key material into every log line and error report that formats a config.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StcConfig")
            .field("stc_seed", &"[redacted]")
            .field("trellis_height", &self.trellis_height)
            .field("max_bpp", &self.max_bpp)
            .finish()
    }
}

#[cfg(feature = "ffi-stc")]
extern "C" {
    /// Embeds `message` into `cover` and writes the result to `stego`.
    ///
    /// `profile` points to the per-position cost vector; with `use_float` set it
    /// is read as `float[cover_length]`, which is the layout this crate uses.
    /// Returns the total distortion of the chosen trellis path.
    fn stc_embed(
        cover: *const c_uchar,
        cover_length: c_uint,
        message: *const c_uchar,
        message_length: c_uint,
        profile: *const c_void,
        use_float: bool,
        stego: *mut c_uchar,
        constraint_height: c_uint,
    ) -> c_uint;

    /// Recovers `message_length` message bits from `stego`.
    fn stc_extract(
        stego: *const c_uchar,
        stego_length: c_uint,
        message: *mut c_uchar,
        message_length: c_uint,
        constraint_height: c_uint,
    );
}

/// Embeds `payload` into the cover bits of `pixels`, in place.
///
/// `pixels` holds one binary cover symbol per embedding position — in practice
/// the least significant bit of each selected sample — and `cost` holds the
/// price of flipping each of them, in the same order. On success the slice has
/// been overwritten with the stego symbols and the return value is the number of
/// positions that changed.
///
/// # Errors
///
/// Returns [`StcError::LengthMismatch`] when the two vectors disagree in
/// length, [`StcError::PayloadExceedsCapacity`] when the payload needs more bits
/// than [`MAX_BPP`] allows, [`StcError::InvalidCostMap`] when a cost is negative
/// or not finite, [`StcError::FfiError`] when the cover is too large to describe
/// to the library, and [`StcError::FeatureNotEnabled`] when the crate was built
/// without `ffi-stc`. Every check runs before the foreign call, so a rejected
/// input never reaches `unsafe` code.
pub fn stc_encode_safe(
    pixels: &mut [u8],
    cost: &[f32],
    payload: &[u8],
    config: &StcConfig,
) -> Result<usize, StcError> {
    encode(pixels, cost, payload, config)
}

/// Recovers `payload_len_bits` payload bits from the stego symbols in `pixels`.
///
/// The extraction path needs no cost map: the syndrome is a function of the
/// stego vector alone, which is exactly what makes it recoverable by a receiver
/// who never saw the cover.
///
/// The returned vector is the repacked payload, `ceil(payload_len_bits / 8)`
/// bytes long, with any padding bits of the final byte left zero. It is
/// plaintext-adjacent material and **must** be wrapped in
/// [`zeroize::Zeroizing`] by the caller — this function cannot do it on the
/// caller's behalf without dictating the return type of the whole pipeline.
///
/// # Errors
///
/// Returns [`StcError::PayloadExceedsCapacity`] when more bits are requested
/// than [`MAX_BPP`] allows over this cover, [`StcError::FfiError`] when the
/// cover is too large to describe to the library, and
/// [`StcError::FeatureNotEnabled`] when the crate was built without `ffi-stc`.
pub fn stc_decode_safe(
    pixels: &[u8],
    payload_len_bits: usize,
    config: &StcConfig,
) -> Result<Vec<u8>, StcError> {
    decode(pixels, payload_len_bits, config)
}

/// Real encoder, compiled only when the foreign library is linked in.
#[cfg(feature = "ffi-stc")]
fn encode(
    pixels: &mut [u8],
    cost: &[f32],
    payload: &[u8],
    config: &StcConfig,
) -> Result<usize, StcError> {
    // Pre-condition (a) — the two vectors must describe the same positions.
    if pixels.len() != cost.len() {
        return Err(StcError::LengthMismatch {
            pixels: pixels.len(),
            costs: cost.len(),
        });
    }

    // Pre-condition (b) — the payload must fit under the bits-per-pixel ceiling.
    let payload_bits = payload.len().saturating_mul(8);
    let capacity_bits = config.capacity_bits(pixels.len());
    if payload_bits > capacity_bits {
        return Err(StcError::PayloadExceedsCapacity {
            payload_bits,
            capacity_bits,
        });
    }

    // Pre-condition (c) — the library reads the costs as raw floats and has no
    // way to reject a NaN; a single one would poison the path metric and make
    // the trellis choose arbitrarily.
    if !cost.iter().all(|&value| value.is_finite() && value >= 0.0) {
        return Err(StcError::InvalidCostMap);
    }

    let cover_length = to_c_uint(pixels.len())?;
    let message = unpack_bits(payload);
    let message_length = to_c_uint(message.len())?;

    // Written by the library; kept separate from `pixels` so that the cover it
    // reads and the stego it writes are two distinct allocations.
    let mut stego = vec![0u8; pixels.len()];

    // SAFETY:
    //
    // * Pointer validity. `pixels`, `cost`, `message` and `stego` are live Rust
    //   slices for the whole call, so their pointers are non-null, properly
    //   aligned and readable — or writable, for `stego` — for the lengths given.
    //   Those lengths are the slices' own, converted above with a range check,
    //   so the library is never told a buffer is larger than it is. `cost` is
    //   `&[f32]`, which is exactly the `float[cover_length]` that `use_float`
    //   selects, and `cover_length` equals `cost.len()` by pre-condition (a).
    // * Aliasing. The cover argument and the stego argument point at different
    //   allocations: the library writes only through `stego`, which nothing else
    //   borrows, and reads through `pixels`, `cost` and `message`, which are
    //   shared borrows for the duration of the call. No `&mut` and `&` to the
    //   same bytes cross the boundary. `pixels` is only written afterwards, in
    //   Rust, once the call has returned.
    // * Escaping pointers. Assumed invariant 2 of the module documentation: the
    //   library retains none of these pointers, so none of them has to outlive
    //   the call.
    // * Unwinding. Assumed invariant 3: no C++ exception escapes. Nothing on the
    //   Rust side could observe one if it did.
    let _distortion = unsafe {
        stc_embed(
            pixels.as_ptr(),
            cover_length,
            message.as_ptr(),
            message_length,
            cost.as_ptr().cast::<c_void>(),
            true,
            stego.as_mut_ptr(),
            config.trellis_height,
        )
    };

    // Counted before the copy, and in Rust rather than from the return value:
    // the library reports its own distortion measure, whose scale depends on the
    // cost vector, whereas the pipeline needs the plain change count.
    let changes = pixels
        .iter()
        .zip(stego.iter())
        .filter(|(cover, stego)| cover != stego)
        .count();

    pixels.copy_from_slice(&stego);

    Ok(changes)
}

/// Stub encoder for builds without the foreign library.
#[cfg(not(feature = "ffi-stc"))]
fn encode(
    pixels: &mut [u8],
    cost: &[f32],
    payload: &[u8],
    config: &StcConfig,
) -> Result<usize, StcError> {
    let _ = (pixels, cost, payload, config);

    Err(StcError::FeatureNotEnabled)
}

/// Real decoder, compiled only when the foreign library is linked in.
#[cfg(feature = "ffi-stc")]
fn decode(
    pixels: &[u8],
    payload_len_bits: usize,
    config: &StcConfig,
) -> Result<Vec<u8>, StcError> {
    let capacity_bits = config.capacity_bits(pixels.len());
    if payload_len_bits > capacity_bits {
        return Err(StcError::PayloadExceedsCapacity {
            payload_bits: payload_len_bits,
            capacity_bits,
        });
    }

    // No bits requested, nothing to ask the library for. Returned here so that
    // the call below never receives a zero-length output buffer.
    if payload_len_bits == 0 {
        return Ok(Vec::new());
    }

    let stego_length = to_c_uint(pixels.len())?;
    let message_length = to_c_uint(payload_len_bits)?;

    // One byte per recovered bit, per the vector convention of the library.
    // Wiped on drop: these are the payload bits themselves.
    let mut message = Zeroizing::new(vec![0u8; payload_len_bits]);

    // SAFETY:
    //
    // * Pointer validity. `pixels` is a live shared borrow and `message` a live
    //   owned buffer for the whole call; both pointers are non-null, aligned and
    //   valid for the lengths passed, which are the buffers' own lengths after
    //   the range check above.
    // * Aliasing. The two buffers are distinct allocations, the first read-only
    //   and the second write-only from the library's point of view, so the
    //   unique borrow of `message` never overlaps the shared borrow of `pixels`.
    // * Escaping pointers and unwinding. Assumed invariants 2 and 3 of the
    //   module documentation, exactly as in `encode`.
    unsafe {
        stc_extract(
            pixels.as_ptr(),
            stego_length,
            message.as_mut_ptr(),
            message_length,
            config.trellis_height,
        );
    }

    Ok(pack_bits(&message))
}

/// Stub decoder for builds without the foreign library.
#[cfg(not(feature = "ffi-stc"))]
fn decode(
    pixels: &[u8],
    payload_len_bits: usize,
    config: &StcConfig,
) -> Result<Vec<u8>, StcError> {
    let _ = (pixels, payload_len_bits, config);

    Err(StcError::FeatureNotEnabled)
}

/// Narrows a Rust length to the `unsigned int` the library takes.
///
/// A cover with more positions than a C `unsigned int` can count would wrap
/// silently and hand the library a length far smaller than the buffer, so the
/// conversion is a checked one and refuses instead.
#[cfg(feature = "ffi-stc")]
fn to_c_uint(length: usize) -> Result<c_uint, StcError> {
    c_uint::try_from(length).map_err(|_| {
        StcError::FfiError(format!(
            "vector of {length} elements is larger than the coder can address"
        ))
    })
}

/// Expands packed bytes into one binary symbol per byte, most significant bit
/// first.
///
/// Wiped on drop: the expansion is a copy of the payload.
#[cfg(feature = "ffi-stc")]
fn unpack_bits(packed: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bits = Zeroizing::new(Vec::with_capacity(packed.len().saturating_mul(8)));

    for byte in packed {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }

    bits
}

/// Packs binary symbols back into bytes, most significant bit first.
///
/// The inverse of [`unpack_bits`] for whole bytes. A count that is not a
/// multiple of eight leaves the unused low bits of the final byte at zero,
/// which is why the bit count travels with the payload rather than being
/// inferred from its length.
#[cfg(feature = "ffi-stc")]
fn pack_bits(bits: &[u8]) -> Vec<u8> {
    let mut packed = vec![0u8; bits.len().div_ceil(8)];

    for (index, bit) in bits.iter().enumerate() {
        if bit & 1 == 1 {
            if let Some(byte) = packed.get_mut(index / 8) {
                *byte |= 1 << (7 - index % 8);
            }
        }
    }

    packed
}
