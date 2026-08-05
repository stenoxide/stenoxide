//! Layer 5 — pipeline orchestration.
//!
//! Chains layers 1 to 4 with explicit ownership transfer at every step, so
//! each sensitive buffer is dropped and zeroed at the earliest possible point.
//! The extraction path needs no cost map: STC decoding operates on the
//! syndrome of all pixels rather than on a stored position list.
//!
//! # The ownership chain
//!
//! Every step of [`EmbedPipeline::embed`] carries a comment explaining what it
//! hands over and what the borrow checker guarantees at that point. Two of those
//! guarantees are the reason this layer is written the way it is:
//!
//! - **Nothing sensitive outlives its use.** The password dies with the master
//!   key derivation, the master key with its expansion, the plaintext with its
//!   encryption, the ciphertext and the subkeys with the trellis pass. Each is
//!   moved into a scope that ends at that point rather than kept in a variable
//!   the rest of the function could still read.
//! - **The cost map and the samples cannot disagree.** `CostMap<'img>` holds the
//!   borrow of the image, so `pixels_mut()` does not compile while the map is
//!   alive. Embedding into pixels whose costs were computed from different
//!   samples is exactly the mistake that would steer changes into the wrong
//!   regions, and here it is a compile error rather than a convention.
//!
//! # What travels in the container
//!
//! Nothing but bits. No metadata, no salt, no nonce, no length prefix outside
//! the frame described in `frame`: the salt is recomputed from the image, the
//! nonce and the permutation seed are derived from it, and the only thing the
//! receiver is told is how many ciphertext bytes to decode.

pub mod error;

// Readable inside the crate rather than private to this module: `generate`
// writes containers of its own and there is one function in this workspace that
// turns a sample buffer into a PNG on disk.
pub(crate) mod frame;

use std::path::Path;

use zeroize::Zeroizing;

use crate::cost::hill::{CostError, HillCostProvider};
use crate::cost::CostProvider;
use crate::crypto::aead::{
    compress_and_encrypt, decrypt_and_decompress, AEADCipher, AEADError, CryptoError,
    XChaCha20Poly1305Cipher,
};
use crate::crypto::expand::{expand_master_key, DerivedKeys};
use crate::crypto::kdf::{Argon2Kdf, KeyDeriver};
#[cfg(feature = "pqc")]
use crate::crypto::kem::Identity;
use crate::generate::read_generated;
#[cfg(feature = "pqc")]
use crate::generate::{read_generated_for_recipient, read_key_transport};
use crate::image_io::buffer::{CoverSource, ImageBuffer};
use crate::image_io::phash::{
    compute_stable_phash, phash_salt_hypotheses, recover_phash_salt, PHashError, PHashSalt,
};
use crate::image_io::validate::load_and_validate;
use crate::stego::permute::generate_pixel_permutation;
use crate::stego::sizer::{compute_capacity, validate_payload_fits, EmbeddingMode, SizerError};
use crate::stego::stc::{stc_decode_safe, stc_encode_safe, StcConfig};

pub use crate::pipeline::error::{OutputError, PipelineError};

/// Ciphertext bytes decoded provisionally to tell two salt hypotheses apart.
///
/// The figure comes from [`recover_phash_salt`], which decrypts the head of this
/// prefix with the raw XChaCha20 keystream and looks for a Zstandard frame magic
/// number. Sixty-four bytes is one XChaCha20 block, and nothing shorter would
/// let the discriminator seek past the block the AEAD reserves for its one-time
/// MAC key.
const PROVISIONAL_PREFIX_BYTES: usize = 64;

/// What one embedding operation did to the container.
///
/// A measurement of the finished stego image, not a receipt the receiver needs:
/// none of these numbers travels with the payload, and the extraction path
/// recomputes everything it needs from the image itself.
#[derive(Debug)]
pub struct EmbedReport {
    /// Positions whose carrier bit the trellis flipped, across both regions of
    /// the frame.
    pub pixels_modified: usize,
    /// Ciphertext bytes embedded, tag included.
    ///
    /// The compressed and encrypted size, not the length of the message the
    /// caller handed in: the plaintext length is not something the container
    /// carries, and reporting it here would suggest otherwise.
    pub payload_bytes: usize,
    /// Bits embedded per pixel of the container, frame header included.
    ///
    /// The figure the security of the scheme rests on. It is bounded by
    /// [`crate::stego::stc::MAX_BPP`] on each region of the frame, so it can
    /// never reach that ceiling over the image as a whole.
    pub effective_bpp: f32,
    /// Dimensions of the container as `(width, height)`, in pixels.
    pub image_dimensions: (u32, u32),
}

/// What one extraction operation recovered.
#[derive(Debug)]
pub struct ExtractReport {
    /// Ciphertext bytes recovered from the container, tag included.
    ///
    /// Counted before decryption and decompression, so it measures how much of
    /// the container was in use rather than how long the message is — the caller
    /// already holds the plaintext and can measure that itself.
    pub payload_bytes: usize,
}

/// The orchestrator of layers 1 to 4.
///
/// Generic over the three components that have a choice of implementation, so
/// that a test can substitute a cheap key deriver or a stub cost model without
/// any of the code below knowing. The production instantiation is built by
/// [`EmbedPipeline::default_secure`].
pub struct EmbedPipeline<KDF, AEAD, COST> {
    /// Password stretching. Argon2id in production.
    kdf: KDF,
    /// Authenticated encryption. XChaCha20-Poly1305 in production.
    aead: AEAD,
    /// Per-pixel embedding costs. HILL in production.
    cost: COST,
}

impl<KDF, AEAD, COST> EmbedPipeline<KDF, AEAD, COST> {
    /// Assembles a pipeline from its three components.
    ///
    /// Unconstrained on purpose: the bounds belong on the operations, not on
    /// construction, so that a caller can hold a pipeline built from anything
    /// and only meet the requirements when it embeds or extracts.
    pub fn new(kdf: KDF, aead: AEAD, cost: COST) -> Self {
        Self { kdf, aead, cost }
    }
}

impl EmbedPipeline<Argon2Kdf, XChaCha20Poly1305Cipher, HillCostProvider> {
    /// Builds the pipeline this project considers secure: Argon2id at 128 MiB
    /// and four passes, XChaCha20-Poly1305, and the HILL cost model.
    ///
    /// There is no constructor that weakens any of the three. A pipeline whose
    /// components were chosen at run time would look identical at the API
    /// surface to this one and behave nothing like it.
    pub fn default_secure() -> Self {
        Self::new(
            Argon2Kdf::default_secure(),
            XChaCha20Poly1305Cipher::new(),
            HillCostProvider::new(),
        )
    }
}

/// Result of one extraction attempt under a single salt hypothesis.
///
/// A rejection is not an error: with an uncertain hash bit there are two
/// hypotheses, and the first one being wrong is an ordinary step of the
/// protocol, not a failure to report.
enum Attempt {
    /// The payload authenticated and decompressed.
    Recovered {
        /// The recovered message.
        plaintext: Zeroizing<Vec<u8>>,
        /// Ciphertext bytes that were decoded to produce it.
        ciphertext_bytes: usize,
    },
    /// The payload did not authenticate under this hypothesis.
    ///
    /// Carries the provisionally decoded ciphertext prefix, which is what
    /// [`recover_phash_salt`] needs to decide whether the hypothesis or the
    /// password was at fault. The prefix is empty when the length header itself
    /// decoded to nonsense, in which case the discriminator rejects both
    /// hypotheses and the caller moves on to the alternative.
    Rejected(Zeroizing<Vec<u8>>),
}

impl<KDF, AEAD, COST> EmbedPipeline<KDF, AEAD, COST>
where
    KDF: KeyDeriver,
    AEAD: AEADCipher,
    COST: CostProvider<Error = CostError>,
{
    /// Hides `plaintext` in the container at `image_path` and writes the result
    /// to `output_path`.
    ///
    /// Both secrets are taken by value in a [`Zeroizing`] wrapper: the pipeline
    /// becomes their owner and wipes them at the point in the chain where they
    /// stop being needed, which a borrow could not guarantee.
    ///
    /// # Errors
    ///
    /// Returns a [`PipelineError`] wrapping the error of whichever layer refused
    /// the operation: an unusable container, an unstable perceptual hash, a
    /// smooth image, a payload that does not fit, a failure of the coder, or a
    /// file that could not be written.
    pub fn embed(
        &self,
        image_path: &Path,
        plaintext: Zeroizing<Vec<u8>>,
        password: Zeroizing<Vec<u8>>,
        output_path: &Path,
    ) -> Result<EmbedReport, PipelineError> {
        // Step 1 — the container enters the chain. `load_and_validate` is the
        // only producer of an `ImageBuffer`, so from here on the type itself is
        // the proof that every validation gate ran. The pipeline owns it, and
        // will still own it when it is written back out.
        let mut image_buffer = load_and_validate(image_path)?;
        let image_dimensions = image_buffer.dimensions();
        let pixel_count = image_buffer.pixel_count();

        // Step 2 — the salt is a function of the container. Only a shared borrow
        // is taken, so `image_buffer` is untouched and still owned by us.
        let phash_salt = compute_stable_phash(&image_buffer)?;

        // Step 3 — the password is consumed here and nowhere else. Both it and
        // the salt are dropped as soon as the derivation returns: `Zeroizing`
        // wipes the password bytes and `ZeroizeOnDrop` wipes the salt, so
        // neither survives the statement that used it.
        let master_key = self.kdf.derive(password.as_slice(), &phash_salt)?;
        drop(password);
        drop(phash_salt);

        // Step 4 — the master key is expanded and immediately destroyed. It is
        // passed by reference, so `expand_master_key` never owns key material it
        // did not create and the wipe happens here, at the earliest point the
        // chain allows.
        let derived_keys = expand_master_key(&master_key)?;
        drop(master_key);

        // Step 5 — the message becomes ciphertext. The intermediate compressed
        // buffer lives and dies inside `compress_and_encrypt`; the plaintext is
        // dropped the moment it returns, which is the last instant it is needed.
        let ciphertext = compress_and_encrypt(
            plaintext.as_slice(),
            derived_keys.enc_key(),
            derived_keys.nonce(),
            &self.aead,
        )?;
        drop(plaintext);

        // Step 6 — the cost map borrows the image for as long as it lives.
        // INVARIANT: from this line until `drop(cost_map)` the compiler refuses
        // every call to `image_buffer.pixels_mut()`. The samples the map was
        // computed from and the samples the coder will modify are therefore the
        // same samples, and that is checked, not assumed.
        let cost_map = self.cost.compute(&image_buffer)?;

        // Step 7 — capacity is measured and the payload is checked against it
        // before a single position is touched. The frame overhead is charged to
        // the payload here because the sizer measures the container as a whole
        // and knows nothing about the header region.
        let capacity = compute_capacity(&cost_map, EmbeddingMode::Symmetric);
        validate_payload_fits(ciphertext.len() + frame::FRAME_OVERHEAD_BYTES, &capacity)?;

        // Step 8 — the secret visiting order. It depends only on the seed and on
        // the pixel count, both of which the receiver can reproduce.
        let permutation = generate_pixel_permutation(pixel_count, derived_keys.stc_seed());

        // Step 9 — everything the coder needs is copied out of the image and the
        // map, in embedding order. Both reads are shared borrows and coexist
        // happily; what matters is that they are the *last* reads, because the
        // next statement releases the map's borrow and the one after that takes
        // a unique borrow of the samples.
        let mut cover_symbols = frame::gather_cover_symbols(&image_buffer, &permutation);
        let cost_reordered = frame::reorder_costs(cost_map.costs(), &permutation);

        // The copy above is what makes this drop possible, and the drop is what
        // makes `image_buffer` mutable again.
        drop(cost_map);

        // Step 10 — two trellis passes over disjoint regions of the permuted
        // positions: the length header first, then the ciphertext. See
        // [`frame`] for why the length cannot simply ride inside the payload.
        let length_header = frame::encode_length_header(ciphertext.len()).ok_or_else(|| {
            // Unreachable after the capacity check: a container able to carry a
            // ciphertext this long does not exist. Reported as an oversized
            // payload because that is exactly what it is.
            SizerError::PayloadTooLarge {
                payload: ciphertext.len(),
                available: u32::MAX as usize,
                deficit: ciphertext.len().saturating_sub(u32::MAX as usize),
            }
        })?;

        let stc_config = StcConfig::new(*derived_keys.stc_seed());

        let (header_costs, payload_costs) = frame::split_regions(&cost_reordered);
        let (header_cover, payload_cover) = frame::split_regions_mut(&mut cover_symbols);

        let header_changes =
            stc_encode_safe(header_cover, header_costs, &length_header, &stc_config)?;
        let payload_changes = stc_encode_safe(
            payload_cover,
            payload_costs,
            ciphertext.as_slice(),
            &stc_config,
        )?;

        let payload_bytes = ciphertext.len();

        // The coder has taken everything it needed from them, so the ciphertext
        // and every derived key leave memory here: `Zeroizing` wipes the first,
        // `ZeroizeOnDrop` the other two.
        drop(ciphertext);
        drop(derived_keys);
        drop(stc_config);
        drop(cost_reordered);

        // Step 11 — the stego symbols go back into the carrier bits. This is the
        // unique borrow that the cost map was standing in the way of, and it is
        // the only mutation of the container in the whole crate.
        frame::apply_cover_symbols(&mut image_buffer, &permutation, &cover_symbols);
        drop(permutation);
        drop(cover_symbols);

        frame::write_png(&image_buffer, output_path)?;

        // Step 12 — the report is pure metadata. `image_buffer` is dropped as
        // this returns and is deliberately not wiped: its contents are the file
        // just written to disk, so there is nothing in it an attacker could not
        // read there instead.
        let embedded_bits = frame::LENGTH_HEADER_BITS + payload_bytes * 8;

        Ok(EmbedReport {
            pixels_modified: header_changes + payload_changes,
            payload_bytes,
            effective_bpp: embedded_bits as f32 / pixel_count.max(1) as f32,
            image_dimensions,
        })
    }

    /// Recovers the message hidden in the stego image at `stego_path`.
    ///
    /// # Why extraction needs no cost map
    ///
    /// STC decoding operates on the syndrome `H x stego (mod 2)` taken over
    /// *all* the positions of a region. The receiver does not need to know which
    /// pixels were modified, and there is no position list to transmit or store:
    /// it only has to reproduce the permutation, which follows from the same
    /// `stc_seed` derived from the same `MasterKey` derived from the same
    /// password and the same image. That is the whole reason the container
    /// carries no metadata at all — and the reason the expensive half of
    /// embedding, the HILL analysis, has no counterpart here.
    ///
    /// # Why it reads two kinds of container
    ///
    /// A container may have been produced by [`crate::generate`] rather than by
    /// [`EmbedPipeline::embed`], and nothing in the file says which — a marker
    /// would be the one piece of metadata this design does not carry. Both
    /// readings are therefore attempted under one key derivation, and every
    /// failure is the single failure below. The second reading costs a stream
    /// cipher over the container and no second Argon2id pass, because both
    /// constructions derive from the same perceptual hash of the same image.
    ///
    /// # Errors
    ///
    /// Returns a [`PipelineError`] wrapping the error of whichever layer
    /// refused: an unusable file, a hash too unstable to reproduce, a coder
    /// failure, or [`AEADError::AuthenticationFailed`] — which collapses a wrong
    /// password, a wrong image and a damaged payload into one answer on purpose.
    pub fn extract(
        &self,
        stego_path: &Path,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(Zeroizing<Vec<u8>>, ExtractReport), PipelineError> {
        // Step 1 — the stego image goes through the same gates as a cover. A
        // container that would have been refused for embedding cannot be one
        // this crate produced.
        let stego_image = load_and_validate(stego_path)?;

        // Step 2 — the salt hypotheses. One when every hash bit is stable, two
        // when embedding may have pushed a coefficient across the median. The
        // password is not consumed yet: with `k == 1` it may have to stretch
        // more than once, so it is kept until every hypothesis is spent.
        let hypotheses = phash_salt_hypotheses(&stego_image)?;

        // Steps 3 to 8 under the hypothesis the image itself suggests.
        match self.attempt_extract(&stego_image, &hypotheses.primary, password.as_slice())? {
            Attempt::Recovered {
                plaintext,
                ciphertext_bytes,
            } => {
                drop(password);

                Ok((
                    plaintext,
                    ExtractReport {
                        payload_bytes: ciphertext_bytes,
                    },
                ))
            }
            Attempt::Rejected(prefix) => {
                let Some(alternative) = hypotheses.alternative else {
                    // Every hash bit was stable, so the salt was certainly the
                    // right one and the failure is genuine.
                    drop(password);

                    return Err(PipelineError::Crypto(CryptoError::AEADError(
                        AEADError::AuthenticationFailed,
                    )));
                };

                // `k == 1`. The prefix was decoded under the primary hypothesis,
                // so `recover_phash_salt` can only confirm that hypothesis — and
                // that is precisely the question being asked. A confirmation
                // means the seed was right and the payload really is unusable; a
                // rejection means the uncertain bit measured the other way on
                // the cover, and the alternative deserves a full attempt.
                let verdict = recover_phash_salt(
                    &stego_image,
                    password.as_slice(),
                    &self.kdf,
                    prefix.as_slice(),
                );
                drop(prefix);

                let outcome = match verdict {
                    Ok(confirmed) => {
                        drop(confirmed);
                        drop(password);

                        return Err(PipelineError::Crypto(CryptoError::AEADError(
                            AEADError::AuthenticationFailed,
                        )));
                    }
                    Err(PHashError::RecoveryFailed) => {
                        self.attempt_extract(&stego_image, &alternative, password.as_slice())
                    }
                    Err(err) => Err(PipelineError::PHash(err)),
                };

                drop(password);

                match outcome? {
                    Attempt::Recovered {
                        plaintext,
                        ciphertext_bytes,
                    } => Ok((
                        plaintext,
                        ExtractReport {
                            payload_bytes: ciphertext_bytes,
                        },
                    )),
                    Attempt::Rejected(_) => Err(PipelineError::Crypto(CryptoError::AEADError(
                        AEADError::AuthenticationFailed,
                    ))),
                }
            }
        }
    }

    /// Recovers a message that was encapsulated to `identity`, rather than
    /// hidden under a password.
    ///
    /// **Experimental, and compiled only behind the `pqc` feature.**
    ///
    /// The counterpart of [`crate::generate::generate_container_for_recipient`].
    /// The mode is selected by the caller handing over an identity instead of a
    /// password — never guessed from the container, which carries nothing that
    /// says which mode built it and must not.
    ///
    /// # Why this path is not folded into [`EmbedPipeline::extract`]
    ///
    /// Because trying both would cost the expensive half of both. The password
    /// path pays for Argon2id at 128 MiB before it can look at anything; this
    /// one never touches Argon2id at all. Attempting the asymmetric reading
    /// inside the password path would gain nothing — there is no identity to
    /// try it with — and attempting the password readings here would mean
    /// stretching a password nobody supplied.
    ///
    /// # The oracle, and the clock
    ///
    /// Every failure below is the same failure the password path reports, as
    /// the same value: a wrong identity, a container carrying nothing and a
    /// damaged payload are one answer. Decapsulation cannot fail — FIPS 203
    /// specifies implicit rejection, so a ciphertext that was not encapsulated
    /// to this key yields a pseudorandom secret rather than an error — which is
    /// what keeps a wrong identity from short-circuiting: it does the same work
    /// as the right one and dies at the same Poly1305 tag.
    ///
    /// The two modes are not the same *speed*, and that is deliberate rather
    /// than overlooked. This path costs a decapsulation and one pass over the
    /// container, some tens of milliseconds; the password path costs Argon2id
    /// on top of that. But an observer timing this process already knows which
    /// mode is running, because the mode is an argument on the command line and
    /// not a property of the container. What a clock must not separate is the
    /// outcomes *within* one mode, and here it cannot: success and every kind
    /// of failure run the identical sequence up to a tag comparison.
    ///
    /// A caller that unlocked the identity from a file has also, by then, paid
    /// one Argon2id for the file's passphrase — so the two modes end up within
    /// the same order of magnitude of each other in practice.
    ///
    /// # Errors
    ///
    /// Returns a [`PipelineError`] wrapping [`AEADError::AuthenticationFailed`]
    /// for every recoverable failure, or the error of the layer that refused
    /// the file outright.
    #[cfg(feature = "pqc")]
    pub fn extract_with_identity(
        &self,
        stego_path: &Path,
        identity: &Identity,
    ) -> Result<(Zeroizing<Vec<u8>>, ExtractReport), PipelineError> {
        // Step 1 — the same gates a cover goes through, as everywhere else.
        let stego_image = load_and_validate(stego_path)?;

        let rejected = || {
            PipelineError::Crypto(CryptoError::AEADError(AEADError::AuthenticationFailed))
        };

        // Step 2 — the encapsulation, read from the head of the carrier. No key
        // is needed to find it, which is the whole reason it is there; see the
        // `generate` module for why that is free in this construction and not
        // in the embedding one.
        let Some(kem_ciphertext) = read_key_transport(&stego_image) else {
            return Err(rejected());
        };

        // Step 3 — the message keys. Total: any container at all produces some
        // key here, and only the tag below decides whether it was the right one.
        let derived_keys = identity
            .decapsulate(&kem_ciphertext)
            .map_err(|_| rejected())?;
        drop(kem_ciphertext);

        // Step 4 — the payload, and the single failure.
        let outcome = read_generated_for_recipient(&stego_image, &derived_keys, &self.aead);
        drop(derived_keys);

        let (plaintext, ciphertext_bytes) = outcome.map_err(|_| rejected())?;

        Ok((
            plaintext,
            ExtractReport {
                payload_bytes: ciphertext_bytes,
            },
        ))
    }

    /// Runs the extraction chain once, under one candidate salt.
    ///
    /// The inverse of steps 3 to 10 of [`EmbedPipeline::embed`], and the unit the
    /// hypothesis search repeats. Everything it derives — master key, subkeys,
    /// permutation — is local and dropped before it returns, so a failed attempt
    /// leaves nothing behind for the next one to trip over.
    ///
    /// # Why two readings, and why one derivation
    ///
    /// A container may have been generated *around* its payload rather than
    /// embedded into — see [`crate::generate`] — and the two are read by
    /// completely different code. Nothing in the file says which it is, and
    /// nothing may: a flag would be the marker this project has gone to some
    /// trouble not to carry, and a distinct error would let an attacker holding
    /// a candidate password learn which construction produced an image.
    ///
    /// So both are tried and both failures are the same failure. It costs
    /// almost nothing because the expensive step is Argon2id and the two
    /// readings derive from the same perceptual hash of the same image: one
    /// derivation serves both, and the second reading is a stream cipher over
    /// the container and nothing else.
    ///
    /// # Errors
    ///
    /// Returns a [`PipelineError`] only for failures that no other hypothesis
    /// could repair. A payload that does not authenticate is reported as
    /// [`Attempt::Rejected`], because with an uncertain hash bit that is a
    /// question about the salt and not yet an error.
    fn attempt_extract(
        &self,
        stego_image: &ImageBuffer,
        salt: &PHashSalt,
        password: &[u8],
    ) -> Result<Attempt, PipelineError> {
        // Steps 3 and 4 — the same derivation the sender ran, in the same order.
        // Both intermediates are wiped as soon as the next value exists.
        let master_key = self.kdf.derive(password, salt)?;
        let derived_keys = expand_master_key(&master_key)?;
        drop(master_key);

        let outcome = match self.decode_trellis(stego_image, &derived_keys)? {
            recovered @ Attempt::Recovered { .. } => recovered,
            // The trellis found nothing. Under these very keys the container
            // may still be one that was generated around its payload, and that
            // reading is what the prefix would otherwise be discarded for.
            Attempt::Rejected(prefix) => {
                match read_generated(stego_image, &derived_keys, &self.aead) {
                    Ok((plaintext, ciphertext_bytes)) => Attempt::Recovered {
                        plaintext,
                        ciphertext_bytes,
                    },
                    // Every way of failing here is the way the trellis reading
                    // already failed, so the attempt ends exactly as it would
                    // have without this second try — prefix included, because
                    // the salt discriminator upstream still wants it.
                    Err(_) => Attempt::Rejected(prefix),
                }
            }
        };

        drop(derived_keys);

        Ok(outcome)
    }

    /// The Syndrome-Trellis reading of a container, under keys already derived.
    ///
    /// Steps 5 to 10 of the inverse chain. Split from [`Self::attempt_extract`]
    /// so that the derivation above it happens once and serves both readings.
    ///
    /// # Errors
    ///
    /// As [`Self::attempt_extract`]: only failures no other hypothesis could
    /// repair.
    fn decode_trellis(
        &self,
        stego_image: &ImageBuffer,
        derived_keys: &DerivedKeys,
    ) -> Result<Attempt, PipelineError> {
        // Step 5 — the visiting order, reproduced rather than transmitted.
        let permutation =
            generate_pixel_permutation(stego_image.pixel_count(), derived_keys.stc_seed());
        let cover_symbols = frame::gather_cover_symbols(stego_image, &permutation);
        drop(permutation);

        let stc_config = StcConfig::new(*derived_keys.stc_seed());
        let (header_region, payload_region) = frame::split_regions(&cover_symbols);

        // Step 6 — the length header. Its region is a constant number of
        // positions, which is what makes this decode possible at all.
        let header = stc_decode_safe(header_region, frame::LENGTH_HEADER_BITS, &stc_config)?;

        // Step 7 — a header decoded under the wrong seed is uniformly random, so
        // the length it announces has to be judged before it is acted on. An
        // implausible one ends the attempt with an empty prefix, which the
        // discriminator upstream reads as "this hypothesis explains nothing".
        let announced = frame::decode_length_header(&header).unwrap_or(0);
        if announced < frame::MIN_CIPHERTEXT_BYTES
            || announced.saturating_mul(8) > stc_config.capacity_bits(payload_region.len())
        {
            return Ok(Attempt::Rejected(Zeroizing::new(Vec::new())));
        }

        // Step 8 — the payload region, decoded to the exact length announced.
        let ciphertext =
            Zeroizing::new(stc_decode_safe(payload_region, announced * 8, &stc_config)?);
        drop(cover_symbols);
        drop(stc_config);

        // Step 9 — authentication, then decompression. Nothing reaches the
        // Zstandard decoder that the Poly1305 tag has not already vouched for.
        let outcome = decrypt_and_decompress(
            ciphertext.as_slice(),
            derived_keys.enc_key(),
            derived_keys.nonce(),
            &self.aead,
        );

        match outcome {
            Ok(plaintext) => Ok(Attempt::Recovered {
                plaintext,
                ciphertext_bytes: announced,
            }),
            // Step 10 — the tag rejected the payload. Under a hypothesis that
            // may be wrong this says nothing yet, so the head of the ciphertext
            // is handed back for the discriminator to judge.
            Err(CryptoError::AEADError(_)) => Ok(Attempt::Rejected(Zeroizing::new(
                ciphertext
                    .iter()
                    .copied()
                    .take(PROVISIONAL_PREFIX_BYTES)
                    .collect(),
            ))),
            // Decompression failed *after* the tag verified: the key was right
            // and the data is genuinely broken. No other hypothesis can help.
            Err(err) => Err(PipelineError::Crypto(err)),
        }
    }
}
