//! Building a container *around* a payload, instead of hiding a payload inside
//! one.
//!
//! # Who this is for
//!
//! Someone with no usable photograph. A laptop with no comfortable way to move
//! pictures across from a phone, or a camera that only ever emits JPEG or HEIC —
//! both lossy, both leaving the 8x8 grid the validation layer refuses, and
//! neither repaired by converting the file to PNG. Until this mode existed that
//! user had no way through at all.
//!
//! # Why generating is *more* secure than embedding, not less
//!
//! Embedding modifies an image, and a modification is a thing a detector can
//! hunt for; the argument is only ever about how well it is hidden. Generating
//! allows something an embedder cannot do: draw each sample from the cover
//! distribution *conditioned on its least significant bit being the ciphertext
//! bit it must carry*. Rejection sampling does that in about two draws, and
//! then, for a uniform carrier bit,
//!
//! ```text
//! sum over b of  P(sample = v | LSB = b) P(b)  =  P(sample = v)
//! ```
//!
//! exactly, provided the least significant bit of the unconditioned
//! distribution is a fair coin. The container that carries a message and the
//! container that carries nothing are draws from **one** distribution. There
//! are not two hypotheses to separate, so there is no statistic to find and no
//! future detector that changes the answer. The naive construction — overwrite
//! the least significant bit rather than draw conditioned on it — forfeits
//! exactly this, and is measurably worse than doing nothing; the reasoning is
//! with the sampler that refuses to use it.
//!
//! Three consequences follow, and the code below depends on all of them:
//!
//! - **The 0.02 bpp cap does not apply here.** It exists because a photograph's
//!   distribution is unknown to the sender. Here the sender *is* the
//!   distribution, and every sample carries a bit: 1.45 MB in a 2000x2000
//!   container against roughly 7 KB for the embedding path.
//! - **The HILL cost map and the trellis take no part.** There is no cost to
//!   minimise when every position is equally free.
//! - **"One image + one password = one message" holds by construction.** Each
//!   generation is a new container with a different perceptual hash, and
//!   therefore a different salt, key and nonce. For the embedding path that
//!   rule is a matter of the user's discipline; here it cannot be broken.
//!
//! # What this mode does not do
//!
//! **It hides which, not whether.** The two hypotheses it equalises are
//! "generated around a message" and "generated around nothing". It says nothing
//! about "generated" versus "photographed": the container looks like a
//! synthetic texture, and someone looking at a folder of them sees images
//! nobody has an obvious reason to keep. Against "which of these hundred
//! carries the message?" it is a complete answer. Against "why do you have this
//! folder?" it is no answer at all.
//!
//! # Untying the circularity
//!
//! The key comes from the perceptual hash of the container, which now depends
//! on the ciphertext, which depends on the key. The knot unties because the
//! hash reads a 32x32 thumbnail where some four thousand grain samples average
//! away to nothing, and layer 1 already refuses any container whose
//! coefficients sit within `5.0` of their median. So a draft container fixes
//! the hash, the hash fixes the key, and the final container is *checked* to
//! hash the same before anything is written.
//!
//! **The draft never touches the disk.** It is built in memory and handed
//! straight to the gates. A draft on disk would be the original cover, and the
//! original cover not existing is precisely what this mode buys.
//!
//! # The seed is key material
//!
//! There is no cover to subtract, but an adversary who can reproduce the
//! generator's random state can regenerate the container and read the
//! difference — and the confirmation is unmistakable, because the right state
//! reproduces the image and a wrong one differs in millions of samples. So the
//! generator is seeded with 32 bytes from the system CSPRNG and from nothing
//! else: never a timestamp, never a counter, never anything derived from the
//! password. The seed is not persisted, printed or logged anywhere.

mod carrier;
mod texture;

use std::fmt;
use std::path::Path;

use rand::rngs::{StdRng, SysRng};
use rand::{Rng, SeedableRng, TryRng};
use zeroize::Zeroizing;

use crate::cost::hill::HillCostProvider;
use crate::cost::CostProvider;
use crate::crypto::aead::{
    compress, decompress, AEADCipher, AEADError, CryptoError, XChaCha20Poly1305Cipher,
    STENOXIDE_AAD,
};
use crate::crypto::expand::{expand_master_key, DerivedKeys, ExpandError};
use crate::crypto::kdf::{Argon2Kdf, KdfError, KeyDeriver};
use crate::image_io::buffer::{ColorSpace, CoverSource, ImageBuffer};
use crate::image_io::jpeg_detect::detect_jpeg_artifacts;
use crate::image_io::phash::compute_stable_phash;
use crate::image_io::validate::{MAX_PIXELS, MIN_DIMENSION};
use crate::pipeline::error::OutputError;
use crate::pipeline::frame::write_png;

use self::carrier::{draw_free, draw_with_lsb};
use self::texture::Texture;

pub use self::carrier::RejectionExhausted;

/// Smallest side a generated container may have, in pixels.
///
/// Exactly the floor [`crate::image_io::validate`] applies to a container read
/// from disk: a container this mode draws has to be one that mode would accept
/// back, so the two share the number rather than each naming their own. It is
/// also, for the texture, the smallest side whose cell scale the perceptual-hash
/// gate reliably accepts — the reason the side used to be fixed here.
pub const MIN_CONTAINER_SIDE: u32 = MIN_DIMENSION;

/// Largest pixel count a generated container may have.
///
/// The same ceiling the loader refuses above, and for the same reason: a
/// receiver has to analyse whatever a sender draws, and that analysis costs
/// memory linear in the pixel count. A container the sender could draw but the
/// receiver could not load would be useless to both.
pub const MAX_CONTAINER_PIXELS: u64 = MAX_PIXELS;

/// Side of the square container generated when no size is requested.
///
/// The historical default, kept as the behaviour of the size-less call: it is
/// the minimum, so it is the smallest — and therefore least conspicuous — file
/// the mode will produce.
pub const DEFAULT_CONTAINER_SIDE: u32 = MIN_CONTAINER_SIDE;

/// Channels of a generated container. It is written as 8-bit RGB.
const CHANNELS: usize = 3;

/// Bytes of the Poly1305 tag that rides at the end of the ciphertext.
const TAG_BYTES: usize = 16;

/// Bytes of the length header at the head of the encrypted buffer.
///
/// A big-endian `u32` counting the compressed payload that follows it.
const LENGTH_HEADER_BYTES: usize = 4;

/// Texture seeds tried before the attempt is abandoned.
///
/// A field passes the gates at something between two and four seeds in six, so
/// sixty-four candidates turn acceptance into a certainty: `0.67^64` is about
/// `1e-11`.
const MAX_CANDIDATES: u32 = 64;

/// Bytes of the seed the generator is started from.
const SEED_BYTES: usize = 32;

/// The size of the container to draw, checked against the two size gates.
///
/// A validated pair rather than two loose integers: the only way to obtain one
/// is [`ContainerDimensions::new`], which refuses anything the loader would
/// refuse, so no code downstream has to re-check a width or a height. A larger
/// container carries more — capacity is a straight function of its pixel count —
/// but every size this type admits is one a receiver can load and one whose
/// texture feeds the hash gate the same octave the default does; see
/// [`crate::generate::texture`] for why enlarging is safe rather than merely
/// tolerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerDimensions {
    /// Width, in pixels. At least [`MIN_CONTAINER_SIDE`].
    width: u32,
    /// Height, in pixels. At least [`MIN_CONTAINER_SIDE`].
    height: u32,
}

impl ContainerDimensions {
    /// A dimensions pair, if it clears both gates a loaded container is held to.
    ///
    /// # Errors
    ///
    /// Returns [`GenerateError::DimensionsOutOfRange`] when either side is below
    /// [`MIN_CONTAINER_SIDE`], or when the two multiply to more than
    /// [`MAX_CONTAINER_PIXELS`]. The product is taken in [`u64`] so that two
    /// large sides cannot wrap into a small count and slip past the ceiling.
    pub fn new(width: u32, height: u32) -> Result<Self, GenerateError> {
        let out_of_range = || GenerateError::DimensionsOutOfRange {
            width,
            height,
            min_side: MIN_CONTAINER_SIDE,
            max_pixels: MAX_CONTAINER_PIXELS,
        };

        if width < MIN_CONTAINER_SIDE || height < MIN_CONTAINER_SIDE {
            return Err(out_of_range());
        }
        if u64::from(width) * u64::from(height) > MAX_CONTAINER_PIXELS {
            return Err(out_of_range());
        }

        Ok(Self { width, height })
    }

    /// Width of the container, in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Height of the container, in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Ciphertext bytes a container of this size carries.
    ///
    /// One bit per sample, tag included: the ciphertext occupies the container
    /// exactly, to the last sample it can fill.
    fn capacity(self) -> usize {
        self.width as usize * self.height as usize * CHANNELS / 8
    }

    /// Compressed payload bytes a container of this size admits.
    ///
    /// What is left of the capacity once the authentication tag and the length
    /// header are paid for.
    fn payload_capacity(self) -> usize {
        self.capacity().saturating_sub(TAG_BYTES + LENGTH_HEADER_BYTES)
    }
}

impl Default for ContainerDimensions {
    /// The square container the size-less call produces; see
    /// [`DEFAULT_CONTAINER_SIDE`].
    fn default() -> Self {
        Self {
            width: DEFAULT_CONTAINER_SIDE,
            height: DEFAULT_CONTAINER_SIDE,
        }
    }
}

/// What one generation produced.
///
/// None of these figures travels with the container, and none of them is a
/// secret the caller does not already hold: the container is always the same
/// size whatever it carries, which is the point of filling it.
#[derive(Debug)]
pub struct GenerateReport {
    /// Dimensions of the container as `(width, height)`, in pixels.
    pub image_dimensions: (u32, u32),
    /// Compressed payload bytes the container was built around.
    ///
    /// The message after Zstandard, not its length: the plaintext length is not
    /// something the container carries, and reporting it here would suggest
    /// otherwise.
    pub payload_bytes: usize,
    /// Compressed payload bytes a container of this size admits.
    pub capacity_bytes: usize,
}

/// Everything that can go wrong between a plaintext and a generated container.
#[derive(Debug)]
pub enum GenerateError {
    /// The system random number generator could not be read.
    ///
    /// Fatal rather than papered over: every alternative source of a seed is
    /// one an adversary can reproduce, and a container generated from a
    /// guessable seed is one they can regenerate and compare against.
    Entropy(String),
    /// The compressed payload is larger than the requested container can hold.
    PayloadTooLarge {
        /// Payload bytes after compression.
        payload: usize,
        /// Compressed payload bytes the requested container admits.
        available: usize,
        /// How far over the limit the payload is, in bytes.
        deficit: usize,
        /// Side of the smallest square container that would admit this payload,
        /// rounded up to a round figure for quoting to a user, or `None` when
        /// no permitted container is large enough. A caller with a size to
        /// suggest reads it from here rather than solving the quadratic itself.
        recommended_side: Option<u32>,
    },
    /// The requested container size is outside the permitted range.
    DimensionsOutOfRange {
        /// Requested width, in pixels.
        width: u32,
        /// Requested height, in pixels.
        height: u32,
        /// Smallest side either dimension may have.
        min_side: u32,
        /// Largest pixel count the two may multiply to.
        max_pixels: u64,
    },
    /// No candidate texture passed the container gates.
    NoUsableTexture {
        /// Seeds that were tried.
        candidates: u32,
    },
    /// Conditioned sampling could not reach a parity.
    Sampling(RejectionExhausted),
    /// Argon2id password stretching failed.
    Kdf(KdfError),
    /// HKDF-SHA3-512 expansion of the master key failed.
    Expand(ExpandError),
    /// Compression or encryption failed.
    Crypto(CryptoError),
    /// The container could not be written to disk.
    Output(OutputError),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateError::Entropy(message) => write!(
                f,
                "could not read the system random number generator, and a container must not be \
                 generated without it: {message}"
            ),
            GenerateError::PayloadTooLarge {
                payload,
                available,
                deficit,
                ..
            } => write!(
                f,
                "the payload does not fit in the requested container: {payload} bytes after \
                 compression against the {available} it admits, {deficit} bytes over"
            ),
            GenerateError::DimensionsOutOfRange {
                width,
                height,
                min_side,
                max_pixels,
            } => write!(
                f,
                "the requested container is {width}x{height}, which is outside the permitted \
                 range: each side must be at least {min_side} pixels and the two together at \
                 most {max_pixels} pixels"
            ),
            GenerateError::NoUsableTexture { candidates } => write!(
                f,
                "no texture passed the container gates in {candidates} candidates"
            ),
            GenerateError::Sampling(err) => write!(f, "{err}"),
            GenerateError::Kdf(err) => write!(f, "{err}"),
            GenerateError::Expand(err) => write!(f, "{err}"),
            GenerateError::Crypto(err) => write!(f, "{err}"),
            GenerateError::Output(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for GenerateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GenerateError::Sampling(err) => Some(err),
            GenerateError::Kdf(err) => Some(err),
            GenerateError::Expand(err) => Some(err),
            GenerateError::Crypto(err) => Some(err),
            GenerateError::Output(err) => Some(err),
            GenerateError::Entropy(_)
            | GenerateError::PayloadTooLarge { .. }
            | GenerateError::DimensionsOutOfRange { .. }
            | GenerateError::NoUsableTexture { .. } => None,
        }
    }
}

impl From<RejectionExhausted> for GenerateError {
    fn from(err: RejectionExhausted) -> Self {
        GenerateError::Sampling(err)
    }
}

impl From<KdfError> for GenerateError {
    fn from(err: KdfError) -> Self {
        GenerateError::Kdf(err)
    }
}

impl From<ExpandError> for GenerateError {
    fn from(err: ExpandError) -> Self {
        GenerateError::Expand(err)
    }
}

impl From<CryptoError> for GenerateError {
    fn from(err: CryptoError) -> Self {
        GenerateError::Crypto(err)
    }
}

impl From<AEADError> for GenerateError {
    fn from(err: AEADError) -> Self {
        GenerateError::Crypto(CryptoError::AEADError(err))
    }
}

impl From<OutputError> for GenerateError {
    fn from(err: OutputError) -> Self {
        GenerateError::Output(err)
    }
}

/// The side of a comfortable square container for a payload this large.
///
/// The smallest square whose payload capacity clears `payload`, then rounded up
/// to the next hundred pixels — a figure a person can read and repeat, with a
/// little headroom over the exact break-even side rather than sitting right on
/// it. `None` when even the largest permitted container is too small: that is
/// the payload's problem and not a size the user can dial around.
///
/// The rounding never pushes the suggestion past [`MAX_CONTAINER_PIXELS`]; on
/// the rare payload whose break-even side is within a hundred pixels of the
/// ceiling, the exact side is quoted instead of a round one that would not fit.
fn recommended_square_side(payload: usize) -> Option<u32> {
    // capacity(side) = side * side * CHANNELS / 8 - overhead, and a `u8/8`
    // capacity clears `payload` exactly when the sample count reaches
    // `8 * (payload + overhead)`. Everything is taken in `u64`: the product of
    // two sides is what the size gate guards against wrapping, and this is the
    // same product read backwards.
    let overhead = (TAG_BYTES + LENGTH_HEADER_BYTES) as u64;
    let needed_bytes = (payload as u64).checked_add(overhead)?;
    let needed_pixels = needed_bytes.checked_mul(8)?.div_ceil(CHANNELS as u64);

    if needed_pixels > MAX_CONTAINER_PIXELS {
        return None;
    }

    let exact_side = integer_sqrt_ceil(needed_pixels).max(MIN_CONTAINER_SIDE);
    let rounded = exact_side.div_ceil(100).saturating_mul(100);

    // The round figure unless it would spill over the pixel ceiling, in which
    // case the exact break-even side — already known to fit — is quoted.
    let side = if u64::from(rounded) * u64::from(rounded) <= MAX_CONTAINER_PIXELS {
        rounded
    } else {
        exact_side
    };

    Some(side)
}

/// The smallest integer whose square is at least `value`.
///
/// A float square root corrected in both directions rather than trusted: the
/// conversion is exact for the pixel counts this is called with — all below the
/// megapixel ceiling — but the correction costs nothing and removes the last
/// place a rounding error could quote a container one pixel too small.
fn integer_sqrt_ceil(value: u64) -> u32 {
    let mut root = (value as f64).sqrt() as u64;

    while root.saturating_mul(root) < value {
        root += 1;
    }
    while root > 0 && (root - 1).saturating_mul(root - 1) >= value {
        root -= 1;
    }

    u32::try_from(root).unwrap_or(u32::MAX)
}

/// Builds a `dimensions` container around `plaintext` and writes it to
/// `output_path`.
///
/// Both secrets are taken by value in a [`Zeroizing`] wrapper, as in
/// [`crate::pipeline::EmbedPipeline::embed`]: this function becomes their owner
/// and wipes them where they stop being needed.
///
/// `dimensions` is already validated — the only way to hold one is
/// [`ContainerDimensions::new`] — so this function cannot be handed a size the
/// loader would refuse. Pass [`ContainerDimensions::default`] for the historical
/// square container when no particular size is wanted.
///
/// The container it writes does not hide that it was generated. It hides which
/// of several generated containers carries a message; see the module
/// documentation for the difference, which is the whole of what this mode
/// promises.
///
/// # Errors
///
/// Returns a [`GenerateError`] when the system random number generator cannot
/// be read, the compressed payload does not fit the requested size, no candidate
/// texture passes the container gates, a cryptographic step fails, or the file
/// cannot be written.
pub fn generate_container(
    plaintext: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    dimensions: ContainerDimensions,
    output_path: &Path,
) -> Result<GenerateReport, GenerateError> {
    generate(
        &Argon2Kdf::default_secure(),
        plaintext,
        password,
        dimensions,
        output_path,
    )
}

/// [`generate_container`] with the key deriver injected.
///
/// Compiled only under `cfg(test)` or the `test-utils` feature, for the same
/// reason [`Argon2Kdf::low_cost_for_tests`] is: a suite that paid 128 MiB and
/// four hundred milliseconds per candidate would be a suite nobody runs. There
/// is no public constructor that weakens the production path.
///
/// # Errors
///
/// As [`generate_container`].
#[cfg(any(test, feature = "test-utils"))]
pub fn generate_container_with_deriver(
    kdf: &dyn KeyDeriver,
    plaintext: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    dimensions: ContainerDimensions,
    output_path: &Path,
) -> Result<GenerateReport, GenerateError> {
    generate(kdf, plaintext, password, dimensions, output_path)
}

/// The generator proper.
///
/// The sequence, per candidate texture, and why it is in this order:
///
/// 1. Draw the texture field from the CSPRNG.
/// 2. Render a **draft** with grain drawn freely. Its only job is to fix the
///    perceptual hash.
/// 3. Put it through the gates a receiver's loader will apply. A refusal costs
///    another candidate and nothing else.
/// 4. Derive the key from the draft's hash: Argon2id, then HKDF.
/// 5. Fill the container-sized buffer, and encrypt it.
/// 6. Render the **final** container: the same field, grain conditioned on the
///    ciphertext.
/// 7. Check that it still hashes to what the draft hashed to. The margin makes
///    this near-certain, but checking is cheap and its failure would be a
///    container nobody can read.
/// 8. Write the PNG.
///
/// The compression in step 5 is hoisted out of the loop: it does not depend on
/// the key, and doing it once means a payload that cannot fit is refused before
/// a single pixel is rendered rather than a minute later.
fn generate(
    kdf: &dyn KeyDeriver,
    plaintext: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
    dimensions: ContainerDimensions,
    output_path: &Path,
) -> Result<GenerateReport, GenerateError> {
    let cipher = XChaCha20Poly1305Cipher::new();

    // The message becomes its compressed form once, and the plaintext is
    // dropped — and therefore wiped — at the earliest point the chain allows.
    let compressed = compress(plaintext.as_slice())?;
    drop(plaintext);

    let available = dimensions.payload_capacity();
    if compressed.len() > available {
        return Err(GenerateError::PayloadTooLarge {
            payload: compressed.len(),
            available,
            deficit: compressed.len() - available,
            // A square suggestion even for a rectangular request: it is the one
            // shape a single figure describes, and the user is free to spend it
            // on whichever pair of sides they like.
            recommended_side: recommended_square_side(compressed.len()),
        });
    }

    let mut rng = seed_from_system()?;

    for _ in 0..MAX_CANDIDATES {
        let texture = Texture::new(rng.next_u64(), dimensions.width(), dimensions.height());

        // Step 2 and 3. The draft exists only in memory, and only long enough
        // to be judged: it is the cover, and the cover is the thing this mode
        // exists to not leave lying around.
        let draft = render(&texture, dimensions, &mut rng, None)?;
        let Ok(draft_salt) = compute_stable_phash(&draft) else {
            continue;
        };
        if !passes_container_gates(&draft) {
            continue;
        }
        drop(draft);

        // Steps 4 and 5. The password is borrowed rather than consumed: a
        // candidate that fails at step 7 needs it again.
        let master_key = kdf.derive(password.as_slice(), &draft_salt)?;
        let derived_keys = expand_master_key(&master_key)?;
        drop(master_key);

        let ciphertext = seal(&compressed, dimensions, &mut rng, &derived_keys, &cipher)?;
        drop(derived_keys);

        // Steps 6 and 7.
        let container = render(&texture, dimensions, &mut rng, Some(&ciphertext))?;
        drop(ciphertext);

        let Ok(final_salt) = compute_stable_phash(&container) else {
            continue;
        };
        if final_salt.as_bytes() != draft_salt.as_bytes() || shows_jpeg_grid(&container) {
            continue;
        }

        write_png(&container, output_path)?;

        return Ok(GenerateReport {
            image_dimensions: container.dimensions(),
            payload_bytes: compressed.len(),
            capacity_bytes: available,
        });
    }

    Err(GenerateError::NoUsableTexture {
        candidates: MAX_CANDIDATES,
    })
}

/// A generator seeded with [`SEED_BYTES`] bytes from the system CSPRNG.
///
/// The seed is wiped as soon as the generator holds it. The generator's own
/// state cannot be wiped from outside — `StdRng` exposes no way to reach it —
/// which is why the seed is the thing that is guarded and why it is drawn from
/// the operating system rather than from anything reproducible.
///
/// # Errors
///
/// Returns [`GenerateError::Entropy`] when the system generator cannot be read.
/// There is no fallback on purpose.
fn seed_from_system() -> Result<StdRng, GenerateError> {
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);

    SysRng
        .try_fill_bytes(seed.as_mut_slice())
        .map_err(|err| GenerateError::Entropy(err.to_string()))?;

    let rng = StdRng::from_seed(*seed);
    drop(seed);

    Ok(rng)
}

/// Whether a candidate would survive the journey to a receiver.
///
/// The gates of layer 1 and of the cost layer, applied to a buffer that never
/// went through a file. That is deliberate: [`crate::image_io::validate::load_and_validate`]
/// is the only public way to obtain an [`ImageBuffer`], and it needs a path —
/// but this code lives inside the crate, so it can build the buffer directly
/// and hand it to the very same analyses. The perceptual hash is checked by the
/// caller, which needs its value rather than its verdict.
///
/// The cost model has no part in the embedding here and is checked anyway: it
/// is what `scan` runs, so a container that failed it would be one the tool
/// itself reports as unusable.
fn passes_container_gates(image: &ImageBuffer) -> bool {
    !shows_jpeg_grid(image) && HillCostProvider::new().compute(image).is_ok()
}

/// Whether the block detector of layer 1 would read a JPEG grid in `image`.
///
/// Applied to the final container as well as to the draft, unlike the cost
/// model: the detector samples blocks at random and it is the final container
/// that will be handed to it, whereas the cost model measures the texture
/// energy of a field the two share.
fn shows_jpeg_grid(image: &ImageBuffer) -> bool {
    let (width, height) = image.dimensions();

    detect_jpeg_artifacts(image.pixels(), width, height, image.color_space()).is_some()
}

/// Renders one container.
///
/// With `carrier` present, the least significant bit of every sample is drawn
/// to equal the corresponding ciphertext bit, most significant bit of each byte
/// first. Samples past the end of the ciphertext are drawn freely, which for
/// the geometry this mode uses is none of them: the ciphertext is sized to fill
/// the container exactly.
///
/// # Errors
///
/// Returns [`GenerateError::Sampling`] if conditioned sampling fails to
/// converge, which no base level this crate's texture produces can cause.
fn render(
    texture: &Texture,
    dimensions: ContainerDimensions,
    rng: &mut StdRng,
    carrier: Option<&[u8]>,
) -> Result<ImageBuffer, GenerateError> {
    let (width, height) = (dimensions.width(), dimensions.height());
    let mut samples = vec![0u8; width as usize * height as usize * CHANNELS];
    let carrier_bits = carrier.map_or(0, |bytes| bytes.len() * 8);

    let mut position = 0usize;
    for y in 0..height {
        for x in 0..width {
            // Once per pixel rather than once per channel: the field is a
            // property of the position, and the three channels are tints of it.
            let base_levels = texture.base_levels(x, y);

            for &base in base_levels.iter() {
                let value = match carrier {
                    Some(bytes) if position < carrier_bits => {
                        // In range: `carrier_bits` is `bytes.len() * 8`.
                        let byte = bytes.get(position / 8).copied().unwrap_or(0);
                        let bit = (byte >> (7 - position % 8)) & 1;
                        draw_with_lsb(rng, base, bit)?
                    }
                    _ => draw_free(rng, base),
                };

                if let Some(sample) = samples.get_mut(position) {
                    *sample = value;
                }
                position += 1;
            }
        }
    }

    Ok(ImageBuffer::new(samples, width, height, ColorSpace::Rgb8))
}

/// Builds the buffer the container is filled with, and encrypts it.
///
/// The plaintext of that one encryption is the whole container:
///
/// ```text
/// [u32 big-endian: compressed length][zstd(message)][random padding]
/// ```
///
/// # Why it is filled to the last byte
///
/// Two properties, and neither is optional:
///
/// 1. **The receiver cannot derive the length from anything else.** Zstandard
///    returns slightly *more* than it was given on incompressible input, so the
///    compressed length is not a function of any quantity a receiver holds. It
///    has to travel, and it travels inside the authenticated plaintext.
/// 2. **Every container is the same size whatever it carries**, so the size of
///    the message does not leak. A ciphertext cut to the exact length of the
///    payload would leak it in full.
///
/// The padding is drawn from the CSPRNG rather than left as zeros. It is
/// encrypted either way, but padding with structure is a temptation with no
/// upside.
///
/// # Errors
///
/// Returns [`GenerateError::Crypto`] if the cipher refuses the buffer.
fn seal(
    compressed: &[u8],
    dimensions: ContainerDimensions,
    rng: &mut StdRng,
    keys: &DerivedKeys,
    cipher: &dyn AEADCipher,
) -> Result<Zeroizing<Vec<u8>>, GenerateError> {
    let plaintext_len = dimensions.capacity().saturating_sub(TAG_BYTES);

    let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext_len));
    // Checked against `payload_capacity` by the caller, so the conversion holds
    // for any container geometry this crate can build.
    let announced = u32::try_from(compressed.len()).unwrap_or(u32::MAX);
    buffer.extend_from_slice(&announced.to_be_bytes());
    buffer.extend_from_slice(compressed);

    let filled = buffer.len();
    buffer.resize(plaintext_len, 0);
    if let Some(padding) = buffer.get_mut(filled..) {
        rng.fill_bytes(padding);
    }

    let ciphertext = cipher.encrypt(keys.enc_key(), keys.nonce(), &buffer, STENOXIDE_AAD)?;
    drop(buffer);

    Ok(ciphertext)
}

/// Reads the payload out of a container that was generated around it.
///
/// The counterpart of [`generate`], and the second of the two readings
/// [`crate::pipeline::EmbedPipeline::extract`] tries. It needs no cost map, no
/// permutation and no trellis: the ciphertext is the least significant bit of
/// every sample, in raster order, and it fills the container exactly.
///
/// Returns the recovered message and the ciphertext bytes it was read from.
///
/// # Errors
///
/// Returns a [`CryptoError`] when the container was not generated around a
/// payload, when it was generated under a different key, or when the
/// authenticated buffer does not hold a payload of the length it announces.
/// The caller must not distinguish these from each other, or from the failure
/// of the other reading: that is the whole reason both are attempted.
pub(crate) fn read_generated(
    image: &ImageBuffer,
    keys: &DerivedKeys,
    cipher: &dyn AEADCipher,
) -> Result<(Zeroizing<Vec<u8>>, usize), CryptoError> {
    let samples = image.pixels();
    let capacity = samples.len() / 8;

    if capacity <= TAG_BYTES + LENGTH_HEADER_BYTES {
        return Err(CryptoError::AEADError(AEADError::AuthenticationFailed));
    }

    let ciphertext = Zeroizing::new(gather_carrier_bits(samples, capacity));
    let buffer = cipher.decrypt(keys.enc_key(), keys.nonce(), &ciphertext, STENOXIDE_AAD)?;

    // Past this line the tag has vouched for every byte, so a malformed header
    // is damage rather than a wrong key — the same distinction the embedding
    // path draws between authentication and decompression.
    let Some(header) = buffer.get(..LENGTH_HEADER_BYTES) else {
        return Err(CryptoError::DecompressionError(
            "the authenticated buffer is shorter than its own length header".to_owned(),
        ));
    };
    let announced = header
        .try_into()
        .map(|bytes: [u8; LENGTH_HEADER_BYTES]| u32::from_be_bytes(bytes) as usize)
        .unwrap_or(0);

    let Some(body) = buffer.get(LENGTH_HEADER_BYTES..LENGTH_HEADER_BYTES + announced) else {
        return Err(CryptoError::DecompressionError(
            "the authenticated buffer announces more payload than it holds".to_owned(),
        ));
    };

    let plaintext = decompress(body)?;
    drop(buffer);

    Ok((plaintext, capacity))
}

/// Collects the least significant bit of the first `bytes * 8` samples.
///
/// Most significant bit of each output byte first, which is the order
/// [`render`] writes them in.
fn gather_carrier_bits(samples: &[u8], bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];

    for (position, sample) in samples.iter().enumerate().take(bytes * 8) {
        if let Some(byte) = out.get_mut(position / 8) {
            *byte |= (sample & 1) << (7 - position % 8);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use crate::crypto::kdf::MasterKey;

    /// Keys that are not derived from any container, for the buffer-level tests
    /// below. Nothing here is about the derivation.
    fn keys() -> DerivedKeys {
        expand_master_key(&MasterKey::new([0x3Cu8; 32])).expect("expansion must succeed")
    }

    /// The container is filled to the last sample it can carry.
    #[test]
    fn the_ciphertext_is_sized_to_the_container() {
        let default = ContainerDimensions::default();
        let samples = default.width() as usize * default.height() as usize * CHANNELS;

        assert_eq!(default.capacity(), samples / 8);
        assert_eq!(default.capacity(), 1_500_000);
        assert_eq!(
            default.payload_capacity(),
            1_500_000 - TAG_BYTES - LENGTH_HEADER_BYTES
        );
    }

    /// Capacity is a straight function of the pixel count, square or not.
    ///
    /// The whole reason a larger container fits a larger payload: every sample
    /// carries one bit, so the admitted payload grows with `width * height` and
    /// a rectangle admits exactly what a square of the same area does.
    #[test]
    fn capacity_follows_the_pixel_count() {
        let square = ContainerDimensions::new(4000, 4000).expect("within range");
        let rectangle = ContainerDimensions::new(2000, 8000).expect("within range");

        assert_eq!(square.capacity(), 4000 * 4000 * CHANNELS / 8);
        assert_eq!(square.capacity(), rectangle.capacity());
        assert!(square.capacity() > ContainerDimensions::default().capacity());
    }

    /// The size gates refuse a side below the floor and a product above the cap.
    #[test]
    fn dimensions_are_held_to_both_gates() {
        assert!(ContainerDimensions::new(MIN_CONTAINER_SIDE, MIN_CONTAINER_SIDE).is_ok());

        let too_short = ContainerDimensions::new(MIN_CONTAINER_SIDE - 1, MIN_CONTAINER_SIDE)
            .map(|_| ())
            .expect_err("a side below the floor must be refused");
        assert!(matches!(
            too_short,
            GenerateError::DimensionsOutOfRange { .. }
        ));

        // A width that alone is fine but multiplies past the ceiling.
        let widest = (MAX_CONTAINER_PIXELS / u64::from(MIN_CONTAINER_SIDE)) as u32;
        assert!(ContainerDimensions::new(widest, MIN_CONTAINER_SIDE).is_ok());
        let over = ContainerDimensions::new(widest + 100, MIN_CONTAINER_SIDE)
            .map(|_| ())
            .expect_err("a product above the ceiling must be refused");
        assert!(matches!(over, GenerateError::DimensionsOutOfRange { .. }));
    }

    /// The recommended side clears the payload, rounds to a hundred, and gives
    /// up only when no permitted container could hold it.
    #[test]
    fn the_recommended_side_is_round_and_sufficient() {
        // The figure from the user report: about 1.78 MB compressed.
        let side = recommended_square_side(1_782_778).expect("a container this size exists");
        assert_eq!(side % 100, 0, "the suggestion must be a round figure");
        assert!(side >= MIN_CONTAINER_SIDE);

        let admitted = ContainerDimensions::new(side, side)
            .expect("the suggestion must be within range")
            .payload_capacity();
        assert!(
            admitted >= 1_782_778,
            "a container of the suggested side must actually hold the payload"
        );
        // And it is not wildly oversized: the previous hundred would not do.
        let admitted_below = ContainerDimensions::new(side - 100, side - 100)
            .expect("within range")
            .payload_capacity();
        assert!(admitted_below < 1_782_778);

        // A payload no permitted container can hold has no suggestion to make.
        let unattainable = (MAX_CONTAINER_PIXELS as usize) * CHANNELS / 8;
        assert!(recommended_square_side(unattainable).is_none());
    }

    /// The carrier bits are written and read in the same order.
    #[test]
    fn the_carrier_round_trips_through_the_samples() {
        let payload = [0b1010_1010u8, 0b0000_1111, 0xFF, 0x00];

        // One sample per bit, carrying nothing but that bit.
        let samples: Vec<u8> = (0..payload.len() * 8)
            .map(|position| {
                let byte = payload[position / 8];
                (byte >> (7 - position % 8)) & 1
            })
            .collect();

        assert_eq!(gather_carrier_bits(&samples, payload.len()), payload);

        // The high bits of a sample are not part of the carrier.
        let noisy: Vec<u8> = samples.iter().map(|bit| bit | 0xF0).collect();
        assert_eq!(gather_carrier_bits(&noisy, payload.len()), payload);
    }

    /// The sealed buffer occupies the whole container, whatever it carries.
    ///
    /// The property that keeps the message size from leaking: a one-byte
    /// payload and a large one produce ciphertexts of exactly the same length.
    #[test]
    fn every_sealed_buffer_is_the_same_size() {
        let mut rng = StdRng::seed_from_u64(5);
        let cipher = XChaCha20Poly1305Cipher::new();
        let keys = keys();
        let dimensions = ContainerDimensions::default();

        for length in [0usize, 1, 4_096, 100_000] {
            let compressed = vec![0x5Au8; length];
            let sealed = seal(&compressed, dimensions, &mut rng, &keys, &cipher)
                .expect("a payload within capacity must seal");

            assert_eq!(sealed.len(), dimensions.capacity(), "payload of {length}");
        }
    }

    /// A sealed buffer reads back through the container-shaped reader.
    ///
    /// Driven without rendering an image: the samples are synthesised from the
    /// ciphertext, which is exactly what a rendered container's least
    /// significant bits are.
    #[test]
    fn a_sealed_payload_is_recovered_by_the_reader() {
        let mut rng = StdRng::seed_from_u64(9);
        let cipher = XChaCha20Poly1305Cipher::new();
        let keys = keys();

        let dimensions = ContainerDimensions::default();
        let message = b"a message that is compressed, sealed and read back".repeat(4);
        let compressed = compress(&message).expect("compression must succeed");
        let sealed = seal(&compressed, dimensions, &mut rng, &keys, &cipher)
            .expect("sealing must succeed");

        let samples: Vec<u8> = (0..sealed.len() * 8)
            .map(|position| {
                let byte = sealed.get(position / 8).copied().unwrap_or(0);
                0x80 | ((byte >> (7 - position % 8)) & 1)
            })
            .collect();
        let image = ImageBuffer::new(
            samples,
            dimensions.width(),
            dimensions.height(),
            ColorSpace::Rgb8,
        );

        match read_generated(&image, &keys, &cipher) {
            Ok((plaintext, bytes)) => {
                assert_eq!(plaintext.as_slice(), message.as_slice());
                assert_eq!(bytes, dimensions.capacity());
            }
            Err(error) => panic!("a sealed payload must be recovered: {error}"),
        }

        // Any other key is an authentication failure, and says nothing more.
        let other = expand_master_key(&MasterKey::new([0x11u8; 32])).expect("expansion");
        let error = read_generated(&image, &other, &cipher)
            .map(|_| ())
            .expect_err("a wrong key must not authenticate");
        assert!(
            matches!(error, CryptoError::AEADError(AEADError::AuthenticationFailed)),
            "got: {error:?}"
        );
    }

    /// A container too small to hold a header is refused as an authentication
    /// failure, like everything else this reader can refuse.
    #[test]
    fn a_container_without_room_for_a_payload_is_refused() {
        let image = ImageBuffer::new(vec![0u8; 64], 4, 4, ColorSpace::Rgb8);
        let error = read_generated(&image, &keys(), &XChaCha20Poly1305Cipher::new())
            .map(|_| ())
            .expect_err("a container with no room must be refused");

        assert!(
            matches!(error, CryptoError::AEADError(AEADError::AuthenticationFailed)),
            "got: {error:?}"
        );
    }

    /// Every failure explains itself, and the chain of causes is wired.
    #[test]
    fn every_failure_explains_itself() {
        let messages = [
            GenerateError::Entropy("no device".to_owned()).to_string(),
            GenerateError::PayloadTooLarge {
                payload: 2_000_000,
                available: 1_499_980,
                deficit: 500_020,
                recommended_side: recommended_square_side(2_000_000),
            }
            .to_string(),
            GenerateError::DimensionsOutOfRange {
                width: 1_000,
                height: 3_000,
                min_side: MIN_CONTAINER_SIDE,
                max_pixels: MAX_CONTAINER_PIXELS,
            }
            .to_string(),
            GenerateError::NoUsableTexture { candidates: 64 }.to_string(),
            GenerateError::Sampling(RejectionExhausted).to_string(),
            GenerateError::from(KdfError::EmptyPassword).to_string(),
            GenerateError::from(ExpandError::HkdfError("too long".to_owned())).to_string(),
            GenerateError::from(AEADError::AuthenticationFailed).to_string(),
            GenerateError::from(OutputError::MalformedBuffer).to_string(),
        ];

        for message in &messages {
            assert!(!message.is_empty());
        }

        assert!(messages[0].contains("no device"));
        assert!(messages[1].contains("2000000") && messages[1].contains("500020"));
        assert!(messages[2].contains("1000x3000") && messages[2].contains("2000"));
        assert!(messages[3].contains("64"));

        // Only the variants that wrap another error have a cause to chain to.
        assert!(std::error::Error::source(&GenerateError::from(KdfError::EmptyPassword)).is_some());
        assert!(
            std::error::Error::source(&GenerateError::NoUsableTexture { candidates: 1 }).is_none()
        );
        assert!(std::error::Error::source(&GenerateError::DimensionsOutOfRange {
            width: 1_000,
            height: 3_000,
            min_side: MIN_CONTAINER_SIDE,
            max_pixels: MAX_CONTAINER_PIXELS,
        })
        .is_none());
    }

    /// The seed comes from the system generator, and it produces a working one.
    #[test]
    fn the_generator_is_seeded_from_the_system() {
        let mut first = seed_from_system().expect("the system generator must be readable");
        let mut second = seed_from_system().expect("the system generator must be readable");

        // Two draws that agreed would mean the seed was not what it claims.
        assert_ne!(first.next_u64(), second.next_u64());
    }
}
