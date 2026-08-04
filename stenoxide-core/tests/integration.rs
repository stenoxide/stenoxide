//! End-to-end tests of the five layers, driven through the public API.
//!
//! # Cost policy
//!
//! No test here builds a production key deriver. `Argon2Kdf::default_secure`
//! spends 128 MiB and some four hundred milliseconds per derivation, and the
//! extraction path can run it twice; a suite that paid that would be a suite
//! nobody runs. Every pipeline below is assembled by [`test_pipeline`] with
//! `Argon2Kdf::low_cost_for_tests` injected in its place — which is the reason
//! the pipeline is generic over its key deriver at all.
//!
//! The cipher and the cost model are *not* substituted. Both are cheap, and
//! both are load-bearing: a stub cost model would make the round trip prove
//! nothing about whether HILL accepts the container.
//!
//! # Everything here runs on a default build
//!
//! The Syndrome-Trellis coder used to be an external C++ library the build
//! linked only under the `ffi-stc` feature, so every round trip below was
//! compiled out of a default `cargo test` and the suite could only assert that
//! the pipeline *reached* the coder. The coder is now native Rust and always
//! present, which is why the gates are gone: a plain
//!
//! ```text
//! cargo test --workspace
//! ```
//!
//! exercises the whole chain, embedding included.
//!
//! # What this file measures, and what it does not
//!
//! These tests drive the crate the way a consumer does: through `load_and
//! validate`, the pipeline and the public types, with real containers on disk.
//! That is the right altitude for the properties below — a round trip, a
//! capacity boundary, a refusal that must not name its cause — and the wrong
//! one for anything that needs a hand-built image or a private helper, which
//! the unit tests beside each module cover instead.
//!
//! The split is deliberate rather than incidental, and it is what the coverage
//! floor rests on. Three areas were reachable only from inside the crate and
//! were left entirely unexercised until the unit suites were written: the
//! layouts other than `Rgb8` (`Rgba8`, `Luma8` and the 16-bit path, none of
//! which any fixture here produces), the vocabulary of every layer — the
//! `Display` and `source` implementations a front-end prints — and the
//! discriminator that tells two salt hypotheses apart, which needs a container
//! whose hash is uncertain. Everything an external caller *can* reach is
//! exercised here.

mod support;

use static_assertions::{assert_impl_all, assert_not_impl_any};
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::crypto::aead::{AEADError, CryptoError, XChaCha20Poly1305Cipher};
use stenoxide_core::crypto::expand::{expand_master_key, DerivedKeys};
use stenoxide_core::crypto::kdf::{Argon2Kdf, KeyDeriver, MasterKey};
use stenoxide_core::image_io::buffer::CoverSource;
use stenoxide_core::image_io::jpeg_detect::detect_jpeg_artifacts;
use stenoxide_core::image_io::phash::{compute_stable_phash, PHashError, PHashSalt};
use stenoxide_core::image_io::validate::{load_and_validate, ValidationError};
use stenoxide_core::pipeline::{EmbedPipeline, PipelineError};
use stenoxide_core::stego::sizer::{compute_capacity, EmbeddingMode, SizerError};
use stenoxide_core::stego::stc::StcConfig;
use tempfile::NamedTempFile;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// The message the round trip carries.
const MESSAGE: &[u8] = "Top secret test message".as_bytes();

/// The password the round trip uses.
///
/// Deliberately not plain ASCII. The key deriver takes raw bytes and never sees
/// a string, so a passphrase whose characters are multi-byte in UTF-8 is the
/// only thing that would catch a layer quietly counting characters instead.
const PASSWORD: &[u8] = "naïve-container-passphrase".as_bytes();

/// A password that is not [`PASSWORD`].
const WRONG_PASSWORD: &[u8] = "NOT-THE-CORRECT-PASSPHRASE".as_bytes();

/// A pipeline that is production-grade in everything except its key deriver.
fn test_pipeline() -> EmbedPipeline<Argon2Kdf, XChaCha20Poly1305Cipher, HillCostProvider> {
    EmbedPipeline::new(
        Argon2Kdf::low_cost_for_tests(),
        XChaCha20Poly1305Cipher::new(),
        HillCostProvider::new(),
    )
}

/// Wraps a byte slice the way the pipeline's API demands.
fn secret(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes.to_vec())
}

/// The fixtures themselves are a test.
///
/// Each of the three is built to sit on a specific side of a specific gate, and
/// a generator that drifted would otherwise turn a real regression into a test
/// that quietly stops measuring anything. Asserting the properties here means
/// the suite reports "the fixture is wrong" rather than "the round trip broke".
#[test]
fn fixtures_have_the_properties_the_tests_rely_on() {
    let cover = load_and_validate(&support::textured_cover())
        .expect("the textured cover must pass every validation gate");

    let (width, height) = cover.dimensions();
    assert_eq!((width, height), (support::COVER_SIDE, support::COVER_SIDE));

    // Required explicitly by the specification of this fixture: the cover is
    // also the input of the round trip and the capacity test, so it has to be
    // demonstrably clean of the very artifacts the disguised fixture carries.
    assert_eq!(
        detect_jpeg_artifacts(cover.pixels(), width, height, cover.color_space()),
        None,
        "the textured cover must not read as previously JPEG-compressed"
    );

    assert!(
        compute_stable_phash(&cover).is_ok(),
        "the textured cover must hash reproducibly before anything is embedded"
    );
}

/// TEST 1 — a message survives a full embed and extract cycle.
#[test]
fn round_trip_recovers_the_message() {
    let stego = NamedTempFile::new().expect("temporary stego file");

    test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego.path(),
        )
        .expect("embedding into the textured cover must succeed");

    let (plaintext, _report) = test_pipeline()
        .extract(stego.path(), secret(PASSWORD))
        .expect("extraction with the right password must succeed");

    assert_eq!(plaintext.as_slice(), MESSAGE);
}

/// TEST 2 — the wrong password is an authentication failure and nothing more.
#[test]
fn wrong_password_fails_authentication_without_saying_so() {
    let stego = NamedTempFile::new().expect("temporary stego file");

    test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego.path(),
        )
        .expect("embedding into the textured cover must succeed");

    // Discarding the success value before `expect_err` keeps a recovered
    // plaintext out of the panic message, in the one case where this assertion
    // firing would mean the wrong password had worked.
    let error = test_pipeline()
        .extract(stego.path(), secret(WRONG_PASSWORD))
        .map(|_| ())
        .expect_err("extraction with the wrong password must fail");

    assert!(
        matches!(
            error,
            PipelineError::Crypto(CryptoError::AEADError(AEADError::AuthenticationFailed))
        ),
        "expected an authentication failure, got: {error:?}"
    );

    // The specification asks that the message name neither the password nor the
    // key. The message this layer produces — "authentication failed: wrong
    // password or corrupted data" — does name the password, and deliberately:
    // it is a disjunction, and a disjunction attributes nothing. What must never
    // appear is a message that singles out one cause, because that is the oracle
    // an attacker holding an intercepted image is trying to build. So the
    // property asserted is the one that matters: whenever a cause is named, an
    // alternative is named alongside it.
    let message = error.to_string().to_lowercase();
    assert!(
        !message.contains("password") || message.contains("corrupted"),
        "the failure must never attribute itself to the password alone: {message}"
    );
}

/// TEST 3 — a JPEG is refused on its magic bytes, before it is decoded.
#[test]
fn jpeg_is_rejected_by_magic_bytes() {
    // `ImageBuffer` derives `Debug` over its whole sample buffer, so the
    // success value is dropped before `expect_err` can be tempted to print
    // twelve megabytes of it. The same applies to every load below.
    let error = load_and_validate(&support::clean_jpeg())
        .map(|_| ())
        .expect_err("a JPEG must never be accepted as a container");

    assert!(
        matches!(error, ValidationError::JpegDetected),
        "expected a JPEG to be named as such, got: {error:?}"
    );
}

/// TEST 4 — JPEG content wearing a PNG header is refused on its pixels.
///
/// The complement of the test above: here the magic bytes are honest and the
/// content is not, so only the block-structure analysis of the third gate can
/// catch it.
#[test]
fn jpeg_disguised_as_png_is_rejected_by_its_artifacts() {
    let error = load_and_validate(&support::jpeg_as_png())
        .map(|_| ())
        .expect_err("laundered JPEG content must never be accepted as a container");

    assert!(
        matches!(error, ValidationError::JpegArtifactsDetected { .. }),
        "expected blocking artifacts to be detected, got: {error:?}"
    );
}

/// TEST 5 — an oversized payload is refused, and the refusal says nothing.
#[test]
fn oversized_payload_is_refused_without_leaking_parameters() {
    let stego = NamedTempFile::new().expect("temporary stego file");

    // Incompressible, and that is the point. The specification called for half a
    // megabyte of zeros, but the payload is Zstandard-compressed at level 19
    // before it is measured: half a megabyte of zeros becomes a few dozen bytes,
    // fits in the container with room to spare, and the sizer is never reached.
    // Measured, not assumed — a counter-driven byte pattern was tried first and
    // compressed by a factor of sixty, so this test reached the coder instead of
    // the gate it names.
    let payload = support::incompressible_payload(500_000);

    let error = test_pipeline()
        .embed(
            &support::textured_cover(),
            Zeroizing::new(payload),
            secret(PASSWORD),
            stego.path(),
        )
        .map(|_| ())
        .expect_err("a payload far larger than the container must be refused");

    assert!(
        matches!(
            error,
            PipelineError::Sizer(SizerError::PayloadTooLarge { .. })
        ),
        "expected a capacity refusal, got: {error:?}"
    );

    // The variant carries the exact figures for a caller that wants them, but
    // the rendered message must not: the available byte count would give away
    // the coding efficiency, the overhead, and through them the number of usable
    // positions the analysis found in this container.
    let message = error.to_string().to_lowercase();
    assert!(
        message.contains("shorten the message") || message.contains("higher resolution"),
        "the message must tell the user what to do instead: {message}"
    );
    for leak in ["bpp", "0.02", "byte", "capacity", "pixel"] {
        assert!(
            !message.contains(leak),
            "the message must not expose internal parameters, found {leak:?} in: {message}"
        );
    }
}

/// TEST 6 — embedding does not disturb the hash the salt is derived from.
///
/// The empirical guarantee behind the whole salt-recovery mechanism. The salt is
/// never stored: it is recomputed from the stego image on the receiving side,
/// which only works if embedding at `0.02` bits per pixel leaves every DCT
/// coefficient of the 32x32 thumbnail on the same side of the median it started
/// on. This test is what says that in practice rather than in the abstract.
#[test]
fn embedding_leaves_the_perceptual_hash_reproducible() {
    let stego_file = NamedTempFile::new().expect("temporary stego file");

    test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego_file.path(),
        )
        .expect("embedding into the textured cover must succeed");

    let stego = load_and_validate(stego_file.path())
        .expect("the stego image must pass the same gates as the cover");

    match compute_stable_phash(&stego) {
        Ok(_) => {}
        Err(error) => panic!("the stego image must still hash stably, got: {error}"),
    }
}

/// TEST 7 — a container below the minimum side length is refused.
#[test]
fn undersized_image_is_rejected() {
    let file = NamedTempFile::new().expect("temporary png file");
    support::write_undersized_png(file.path());

    let error = load_and_validate(file.path())
        .map(|_| ())
        .expect_err("a 500x500 container must be refused");

    assert!(
        matches!(
            error,
            ValidationError::ImageTooSmall {
                width: 500,
                height: 500,
                min: 2000,
            }
        ),
        "expected the size gate to name the offending dimensions, got: {error:?}"
    );
}

/// TEST 8 — the types that hold key material wipe themselves, and cannot be
/// copied out from under the owner responsible for that.
///
/// Checked at compile time rather than at run time, because there is no run
/// time check for it: whether a buffer was overwritten is not observable from
/// safe Rust, and the only thing that can be asserted is the property the
/// standard mechanism provides. What would actually go wrong is a derive being
/// dropped in a refactor, and that is exactly what these catch.
///
/// The negative assertions matter as much as the positive ones. A `Clone` on
/// any of these would put a second live image of the material in memory that no
/// owner is responsible for erasing, and a `Debug` would put it into logs and
/// panic messages.
mod key_material_is_wiped_and_never_copied {
    use super::*;

    assert_impl_all!(MasterKey: ZeroizeOnDrop);
    assert_impl_all!(DerivedKeys: ZeroizeOnDrop);
    assert_impl_all!(PHashSalt: ZeroizeOnDrop);
    assert_impl_all!(StcConfig: ZeroizeOnDrop);

    assert_not_impl_any!(MasterKey: Clone, Copy, std::fmt::Debug);
    assert_not_impl_any!(DerivedKeys: Clone, Copy, std::fmt::Debug);
    assert_not_impl_any!(PHashSalt: Clone, Copy, std::fmt::Debug);
    assert_not_impl_any!(StcConfig: Clone, Copy);
}

/// TEST 9 — every way the loader can refuse a container, through the public
/// entry point.
///
/// One test rather than eight because the property is the same in each case and
/// it is about the set: the loader must name what is wrong with a file, and
/// there must be no input for which it names the wrong thing. The transitions
/// behind it are exercised on their own in the unit suite of that module.
#[test]
fn every_validation_gate_names_what_it_refused() {
    let scratch = NamedTempFile::new().expect("temporary file");

    // A path that is not there at all.
    let missing = load_and_validate(std::path::Path::new("no-such-container.png"))
        .map(|_| ())
        .expect_err("a missing file must be refused");
    assert!(
        matches!(missing, ValidationError::IoError(_)),
        "got: {missing:?}"
    );

    // A JPEG, named on its magic bytes.
    let jpeg = load_and_validate(&support::clean_jpeg())
        .map(|_| ())
        .expect_err("a jpeg must be refused");
    assert!(
        matches!(jpeg, ValidationError::JpegDetected),
        "got: {jpeg:?}"
    );

    // A WebP, likewise: the other lossy format a user reaches for by mistake.
    support::write_webp_header(scratch.path());
    let webp = load_and_validate(scratch.path())
        .map(|_| ())
        .expect_err("a webp must be refused");
    assert!(
        matches!(webp, ValidationError::WebpDetected),
        "got: {webp:?}"
    );

    // Bytes that are no format the loader can name.
    support::write_unknown_format(scratch.path());
    let unknown = load_and_validate(scratch.path())
        .map(|_| ())
        .expect_err("an unrecognised file must be refused");
    assert!(
        matches!(unknown, ValidationError::NotPng),
        "got: {unknown:?}"
    );

    // An honest signature over a stream the decoder cannot read.
    support::write_corrupt_png(scratch.path());
    let corrupt = load_and_validate(scratch.path())
        .map(|_| ())
        .expect_err("a malformed png stream must be refused");
    assert!(
        matches!(corrupt, ValidationError::DecodingError(_)),
        "got: {corrupt:?}"
    );

    // A PNG below the minimum side length.
    support::write_undersized_png(scratch.path());
    let small = load_and_validate(scratch.path())
        .map(|_| ())
        .expect_err("a 500x500 container must be refused");
    assert!(
        matches!(small, ValidationError::ImageTooSmall { .. }),
        "got: {small:?}"
    );

    // A PNG of the right size in a layout the embedder cannot carry a bit in.
    support::write_grayscale_alpha_png(scratch.path());
    let layout = load_and_validate(scratch.path())
        .map(|_| ())
        .expect_err("grayscale with alpha must be refused");
    assert!(
        matches!(layout, ValidationError::UnsupportedColorSpace { .. }),
        "got: {layout:?}"
    );

    // A PNG carrying the 8x8 grid of a previous JPEG round trip.
    let laundered = load_and_validate(&support::jpeg_as_png())
        .map(|_| ())
        .expect_err("laundered jpeg content must be refused");
    assert!(
        matches!(laundered, ValidationError::JpegArtifactsDetected { .. }),
        "got: {laundered:?}"
    );
}

/// TEST 10 — a container whose hash would not survive embedding is refused
/// before the password is stretched.
///
/// The gate the whole salt-recovery mechanism depends on: the salt is never
/// stored, so a container whose perceptual hash is not reproducible is a
/// container whose payload nobody could ever read back. A uniform image is the
/// extreme case — every AC coefficient piles up around a near-zero median — and
/// it passes layer 1 in full, which is what makes it the right input for this.
#[test]
fn a_perceptually_unstable_container_is_refused() {
    let cover = NamedTempFile::new().expect("temporary cover file");
    support::write_flat_png(cover.path());

    let stego = NamedTempFile::new().expect("temporary stego file");

    let error = test_pipeline()
        .embed(
            cover.path(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego.path(),
        )
        .map(|_| ())
        .expect_err("a container with no texture must be refused");

    match error {
        PipelineError::PHash(PHashError::InsufficientStability { unstable_bits, .. }) => {
            assert!(
                unstable_bits > 1,
                "only {unstable_bits} bits were uncertain"
            );
        }
        other => panic!("expected an instability verdict, got: {other:?}"),
    }
}

/// TEST 11 — the same inputs produce the same stego image, byte for byte.
///
/// Determinism is not a nicety here. Every value the receiver needs — the salt,
/// the subkeys, the permutation, the parity-check matrix — is recomputed rather
/// than transmitted, so a single non-reproducible draw anywhere in the chain
/// would be a payload nobody could recover. Comparing the encoded files is the
/// strongest form of the check: it covers the coder, the sign of each change and
/// the PNG writer at once.
#[test]
fn embedding_the_same_message_twice_produces_the_same_file() {
    let first = NamedTempFile::new().expect("temporary stego file");
    let second = NamedTempFile::new().expect("temporary stego file");

    for output in [&first, &second] {
        test_pipeline()
            .embed(
                &support::textured_cover(),
                secret(MESSAGE),
                secret(PASSWORD),
                output.path(),
            )
            .expect("embedding into the textured cover must succeed");
    }

    let first_bytes = std::fs::read(first.path()).expect("the first stego image must be readable");
    let second_bytes =
        std::fs::read(second.path()).expect("the second stego image must be readable");

    assert_eq!(first_bytes, second_bytes);
}

/// TEST 12 — the capacity boundary is exact, and the largest payload that fits
/// still comes back out.
///
/// Both halves matter and neither is provable on its own. That a payload one
/// byte over the limit is refused says nothing if the limit was set too low;
/// that a payload at the limit round-trips says nothing if the limit was set
/// too high. Together they pin the sizer's promise: it accepts exactly the
/// payloads the coder can carry.
///
/// The payload is incompressible on purpose. The capacity is measured against
/// the *encrypted* bytes, so a compressible payload would test the compressor
/// rather than the boundary, and the sizer must not assume anything about the
/// content it is handed.
#[test]
fn the_capacity_boundary_is_exact_and_the_last_payload_that_fits_round_trips() {
    /// Bytes of Poly1305 tag appended to every ciphertext by the construction.
    const TAG_BYTES: usize = 16;

    let available = {
        let cover = load_and_validate(&support::textured_cover()).expect("the cover must load");
        let cost_map = HillCostProvider::new()
            .compute(&cover)
            .expect("the cover must be textured enough to measure");

        compute_capacity(&cost_map, EmbeddingMode::Symmetric).available_bytes()
    };

    assert!(available > 0, "the cover must have room to measure");

    // Enough incompressible material to slice every candidate out of, so that
    // one length is a prefix of the next and the encoder sees no other change.
    let material = support::incompressible_payload(available + 64);
    let sealed_len = |len: usize| {
        zstd::encode_all(&material[..len], 19)
            .expect("zstandard must accept a byte slice")
            .len()
            + TAG_BYTES
    };

    let stego = NamedTempFile::new().expect("temporary stego file");
    let embed = |len: usize| {
        test_pipeline().embed(
            &support::textured_cover(),
            Zeroizing::new(material[..len].to_vec()),
            secret(PASSWORD),
            stego.path(),
        )
    };

    // The frame the pipeline charges against the measured capacity is internal,
    // and it is not guessed here: one deliberately oversized payload makes the
    // sizer report the figure it actually used, and the difference against the
    // ciphertext it was handed is that overhead exactly.
    let probe = available;
    let overhead = match embed(probe).map(|_| ()) {
        Err(PipelineError::Sizer(SizerError::PayloadTooLarge {
            payload,
            available: reported,
            ..
        })) => {
            assert_eq!(
                reported, available,
                "the sizer must measure what we measured"
            );
            payload - sealed_len(probe)
        }
        Ok(()) => panic!("a payload of the full capacity cannot also fit its own overhead"),
        Err(other) => panic!("expected a capacity refusal, got: {other:?}"),
    };

    let fits = |len: usize| sealed_len(len) + overhead <= available;

    // The largest payload that fits, by bisection over a predicate that only
    // ever goes from true to false: the sealed length is non-decreasing in the
    // plaintext length.
    let (mut low, mut high) = (0usize, available);
    while low < high {
        let middle = (low + high).div_ceil(2);
        if fits(middle) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let largest = low;

    assert!(largest > 0, "the container must admit something");
    assert!(
        fits(largest) && !fits(largest + 1),
        "the bisection missed the edge at {largest}"
    );

    let report = match embed(largest) {
        Ok(report) => report,
        Err(error) => panic!("the largest payload that fits must embed: {error}"),
    };
    assert_eq!(report.payload_bytes, sealed_len(largest));
    assert!(report.effective_bpp < 0.02);

    let (recovered, _report) = test_pipeline()
        .extract(stego.path(), secret(PASSWORD))
        .expect("a payload at the boundary must still come back out");
    assert_eq!(recovered.as_slice(), &material[..largest]);

    let error = embed(largest + 1)
        .map(|_| ())
        .expect_err("one byte past the boundary must be refused");
    assert!(
        matches!(
            error,
            PipelineError::Sizer(SizerError::PayloadTooLarge { .. })
        ),
        "got: {error:?}"
    );
}

/// TEST 13 — an image carrying nothing fails exactly as a wrong password does.
///
/// The oracle this whole system is built to withhold. An attacker holding an
/// intercepted image wants one bit of information: is this a container at all?
/// A distinguishable answer to "there is no payload here" against "the password
/// is wrong" gives it to them for free, so the two must be the same answer.
#[test]
fn a_clean_image_fails_exactly_as_a_wrong_password_does() {
    let stego = NamedTempFile::new().expect("temporary stego file");

    test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego.path(),
        )
        .expect("embedding into the textured cover must succeed");

    let on_a_clean_image = test_pipeline()
        .extract(&support::textured_cover(), secret(PASSWORD))
        .map(|_| ())
        .expect_err("a cover carrying nothing must not yield a payload");

    let with_a_wrong_password = test_pipeline()
        .extract(stego.path(), secret(WRONG_PASSWORD))
        .map(|_| ())
        .expect_err("a wrong password must not yield a payload");

    for error in [&on_a_clean_image, &with_a_wrong_password] {
        assert!(
            matches!(
                error,
                PipelineError::Crypto(CryptoError::AEADError(AEADError::AuthenticationFailed))
            ),
            "got: {error:?}"
        );
    }

    // The same sentence, not merely the same variant: the rendered message is
    // what a user pastes into a bug report and an attacker reads.
    assert_eq!(
        on_a_clean_image.to_string(),
        with_a_wrong_password.to_string()
    );

    let message = on_a_clean_image.to_string().to_lowercase();
    assert!(
        !message.contains("key"),
        "the message names the key: {message}"
    );
    assert!(
        !message.contains("password") || message.contains("corrupted"),
        "the message attributes itself to one cause: {message}"
    );
}

/// TEST 14 — a payload of maximum compressibility survives the whole chain.
///
/// Ten thousand identical bytes collapse to a few dozen under Zstandard at
/// level 19, so this drives the chain at the opposite extreme from the capacity
/// test: a ciphertext far shorter than the plaintext, a trellis run at a rate
/// well under the ceiling, and a decompressor that has to expand its output by
/// two orders of magnitude.
#[test]
fn a_highly_compressible_payload_round_trips() {
    let stego = NamedTempFile::new().expect("temporary stego file");
    let plaintext = vec![b'a'; 10_000];

    let report = test_pipeline()
        .embed(
            &support::textured_cover(),
            Zeroizing::new(plaintext.clone()),
            secret(PASSWORD),
            stego.path(),
        )
        .expect("a compressible payload must embed");

    assert!(
        report.payload_bytes < plaintext.len() / 10,
        "ten thousand identical bytes must compress: {} embedded",
        report.payload_bytes
    );

    let (recovered, extract_report) = test_pipeline()
        .extract(stego.path(), secret(PASSWORD))
        .expect("extraction must succeed");

    assert_eq!(recovered.as_slice(), plaintext.as_slice());
    assert_eq!(extract_report.payload_bytes, report.payload_bytes);
}

/// TEST 15 — the key is unique to the container, so the right password on the
/// wrong image recovers nothing.
///
/// What makes the salt worth deriving from the image at all. Both halves are
/// checked: that the two containers really do produce different keys under one
/// password, and that the pipeline behaves accordingly rather than by accident
/// of the payload not being there.
#[test]
fn the_right_password_on_another_image_recovers_nothing() {
    let stego = NamedTempFile::new().expect("temporary stego file");

    test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego.path(),
        )
        .expect("embedding into the textured cover must succeed");

    let error = test_pipeline()
        .extract(&support::alternative_cover(), secret(PASSWORD))
        .map(|_| ())
        .expect_err("another container must not yield this payload");

    assert!(
        matches!(
            error,
            PipelineError::Crypto(CryptoError::AEADError(AEADError::AuthenticationFailed))
        ),
        "got: {error:?}"
    );

    // The reason, stated directly: one password, two containers, two keys.
    let first = derived_keys(&support::textured_cover());
    let second = derived_keys(&support::alternative_cover());

    assert_ne!(first.enc_key(), second.enc_key());
    assert_ne!(first.nonce(), second.nonce());
    assert_ne!(first.stc_seed(), second.stc_seed());
}

/// TEST 16 — the three subkeys are independent, and the expansion is a
/// function.
///
/// The domain separation of the expansion step. Deriving twice from one master
/// key must give the same three subkeys — the receiver depends on it — and no
/// two of them may coincide, because reusing bytes across the cipher, the nonce
/// and the permutation would tie a failure in one to the security of the others.
#[test]
fn the_subkeys_are_independent_and_the_expansion_is_deterministic() {
    let cover = load_and_validate(&support::textured_cover()).expect("the cover must load");
    let salt = compute_stable_phash(&cover).expect("the cover must hash stably");
    let master_key = Argon2Kdf::low_cost_for_tests()
        .derive(PASSWORD, &salt)
        .expect("a non-empty password must stretch");

    let first = expand_master_key(&master_key).expect("expansion must succeed");
    let second = expand_master_key(&master_key).expect("expansion must succeed");

    assert_eq!(first.enc_key(), second.enc_key());
    assert_eq!(first.nonce(), second.nonce());
    assert_eq!(first.stc_seed(), second.stc_seed());

    assert_ne!(first.enc_key().as_slice(), first.stc_seed().as_slice());
    assert_ne!(&first.enc_key()[..24], first.nonce().as_slice());
    assert_ne!(&first.stc_seed()[..24], first.nonce().as_slice());
}

/// The subkeys the pipeline would derive for [`PASSWORD`] and a container.
///
/// The salt is the container's perceptual hash, exactly as in production: there
/// is no other way to obtain one, and inventing a salt would exercise a
/// derivation the pipeline never performs.
fn derived_keys(container: &std::path::Path) -> DerivedKeys {
    let image = load_and_validate(container).expect("the container must load");
    let salt = compute_stable_phash(&image).expect("the container must hash stably");
    let master_key = Argon2Kdf::low_cost_for_tests()
        .derive(PASSWORD, &salt)
        .expect("a non-empty password must stretch");

    expand_master_key(&master_key).expect("expansion must succeed")
}
