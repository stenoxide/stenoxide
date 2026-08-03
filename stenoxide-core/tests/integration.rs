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
//! # What the `ffi-stc` feature changes
//!
//! Syndrome-Trellis coding lives in an external C++ library that the build
//! links only under the `ffi-stc` feature; without it `stc_encode_safe` and
//! `stc_decode_safe` return `StcError::FeatureNotEnabled` and no payload can
//! travel. The tests that need a real coder are therefore compiled only when
//! the feature is on, and the default build asserts instead that the pipeline
//! reaches the coder with everything else already satisfied — see
//! `embedding_stops_at_the_missing_coder`. Running the round trips needs:
//!
//! ```text
//! LIBSDC_PATH=/path/to/libsdc cargo test --workspace --features ffi-stc
//! ```

mod support;

use stenoxide_core::crypto::aead::XChaCha20Poly1305Cipher;
use stenoxide_core::crypto::kdf::Argon2Kdf;
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::image_io::buffer::CoverSource;
use stenoxide_core::image_io::jpeg_detect::detect_jpeg_artifacts;
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::{load_and_validate, ValidationError};
use stenoxide_core::pipeline::{EmbedPipeline, PipelineError};
use stenoxide_core::stego::sizer::SizerError;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

/// The message the round trip carries.
const MESSAGE: &[u8] = "Top secret test message".as_bytes();

/// The password the round trip uses.
///
/// Deliberately not plain ASCII. The key deriver takes raw bytes and never sees
/// a string, so a passphrase whose characters are multi-byte in UTF-8 is the
/// only thing that would catch a layer quietly counting characters instead.
const PASSWORD: &[u8] = "naïve-container-passphrase".as_bytes();

/// A password that is not [`PASSWORD`].
#[cfg(feature = "ffi-stc")]
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
#[cfg(feature = "ffi-stc")]
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
#[cfg(feature = "ffi-stc")]
#[test]
fn wrong_password_fails_authentication_without_saying_so() {
    use stenoxide_core::crypto::aead::{AEADError, CryptoError};

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
        matches!(error, PipelineError::Sizer(SizerError::PayloadTooLarge { .. })),
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
#[cfg(feature = "ffi-stc")]
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

/// What the round trips would test, in a build that cannot run them.
///
/// Compiled only without `ffi-stc`. It drives the same fixture through the same
/// pipeline and asserts that the *only* thing standing between it and an
/// embedded payload is the missing coder: reaching
/// `StcError::FeatureNotEnabled` means the container was loaded, hashed,
/// stretched into a key, encrypted, cost-mapped and found to have room, since
/// every one of those steps precedes the first trellis pass and any of them
/// could have failed first.
///
/// It is not a substitute for the round trip. It is the assurance that when the
/// library is linked in, the round trip is the only thing left to check.
#[cfg(not(feature = "ffi-stc"))]
#[test]
fn embedding_stops_at_the_missing_coder() {
    use stenoxide_core::stego::stc::ffi::StcError;

    let stego = NamedTempFile::new().expect("temporary stego file");

    let error = test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            stego.path(),
        )
        .map(|_| ())
        .expect_err("a build without the coder cannot embed anything");

    assert!(
        matches!(error, PipelineError::Stc(StcError::FeatureNotEnabled)),
        "every layer before the coder must have accepted the fixture, got: {error:?}"
    );
}
