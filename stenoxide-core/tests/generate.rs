//! End-to-end tests of the generative container mode.
//!
//! # Cost policy
//!
//! Generating a container is the most expensive operation in this workspace:
//! two renders of twelve million samples, the analyses of layer 1 and layer 3
//! over four megapixels, and a PNG of incompressible content. Every test below
//! therefore does two things to stay affordable.
//!
//! The key deriver is the cheap one, injected through
//! [`generate_container_with_deriver`] for the same reason the pipeline is
//! generic over it: `Argon2Kdf::default_secure` spends 128 MiB and some four
//! hundred milliseconds per candidate texture. Nothing else is substituted —
//! the cipher, the perceptual hash, the cost model and the block detector are
//! the production ones, because those are what the container has to satisfy.
//!
//! And containers are shared. Three of the tests below ask different questions
//! of one generated container, so it is built once per test binary and cached;
//! only the payload-size sweep and the pair test build their own, because their
//! whole subject is a container built differently.
//!
//! # What is asserted here, and what is asserted elsewhere
//!
//! These tests drive the mode the way a caller does: generate a file, hand the
//! path to the ordinary extraction path, and ask what a receiver would ask.
//! The properties that need a hand-built buffer — that conditioning does not
//! move the sample distribution, that the sealed buffer is always the same
//! size, that the rejection loop is bounded — are unit tests beside the code
//! they are about, where they can be checked without rendering anything.

// The panicking helpers are what a test is written in. The crate-wide bans do
// not reach an integration binary, and this comment is here so that the absence
// of an `allow` is not read as an oversight.

mod support;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::cost::CostProvider;
use stenoxide_core::crypto::aead::XChaCha20Poly1305Cipher;
use stenoxide_core::crypto::expand::expand_master_key;
use stenoxide_core::crypto::kdf::{Argon2Kdf, KeyDeriver};
use stenoxide_core::generate::{generate_container_with_deriver, ContainerDimensions};
use stenoxide_core::image_io::buffer::CoverSource;
use stenoxide_core::image_io::jpeg_detect::detect_jpeg_artifacts;
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::load_and_validate;
use stenoxide_core::pipeline::EmbedPipeline;
use stenoxide_core::stego::sizer::{compute_capacity, EmbeddingMode};
use zeroize::Zeroizing;

/// The message the shared container is generated around.
const MESSAGE: &[u8] = "Generated around this, not modified to hold it".as_bytes();

/// The password every generation below uses.
const PASSWORD: &[u8] = "naïve-container-passphrase".as_bytes();

/// A password that is not [`PASSWORD`].
const WRONG_PASSWORD: &[u8] = "NOT-THE-CORRECT-PASSPHRASE".as_bytes();

/// A payload close to what a container of this size admits.
///
/// The compressed capacity is `1_499_980` bytes and the payload is
/// incompressible, so Zstandard returns slightly *more* than this — which is
/// the point of choosing a figure just under the limit rather than at it.
const NEAR_CAPACITY_BYTES: usize = 1_450_000;

/// Wraps a byte slice the way the generator's API demands.
fn secret(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(bytes.to_vec())
}

/// A pipeline that is production-grade in everything except its key deriver.
fn test_pipeline() -> EmbedPipeline<Argon2Kdf, XChaCha20Poly1305Cipher, HillCostProvider> {
    EmbedPipeline::new(
        Argon2Kdf::low_cost_for_tests(),
        XChaCha20Poly1305Cipher::new(),
        HillCostProvider::new(),
    )
}

/// Generates a default 2000x2000 container around `message` at `name`.
fn generate(name: &str, message: &[u8]) -> PathBuf {
    generate_sized(name, message, ContainerDimensions::default())
}

/// Generates a `dimensions` container around `message` at `name`.
fn generate_sized(name: &str, message: &[u8], dimensions: ContainerDimensions) -> PathBuf {
    let directory = support::fixtures_dir();
    std::fs::create_dir_all(&directory).expect("fixtures directory should be creatable");
    let path = directory.join(name);

    let report = generate_container_with_deriver(
        &Argon2Kdf::low_cost_for_tests(),
        Zeroizing::new(message.to_vec()),
        secret(PASSWORD),
        dimensions,
        &path,
    )
    .expect("a payload within capacity must generate a container");

    assert_eq!(
        report.image_dimensions,
        (dimensions.width(), dimensions.height())
    );
    assert!(
        report.payload_bytes <= report.capacity_bytes,
        "the generator must refuse rather than overfill"
    );

    path
}

/// The container three of the tests below share.
///
/// Built once per test binary. Generation is expensive enough that asking one
/// container several questions is worth the coupling, and the questions are
/// independent of each other.
fn shared_container() -> &'static Path {
    static CONTAINER: OnceLock<PathBuf> = OnceLock::new();

    CONTAINER.get_or_init(|| generate("generated.png", MESSAGE))
}

/// A second container built from the same message and the same password.
///
/// The subject of the pair test: everything a caller controls is identical, so
/// anything that differs between the two comes from the system generator.
fn twin_container() -> &'static Path {
    static CONTAINER: OnceLock<PathBuf> = OnceLock::new();

    CONTAINER.get_or_init(|| generate("generated_twin.png", MESSAGE))
}

/// The subkeys a container and a password derive, through the production hash.
fn derived_keys(container: &Path, password: &[u8]) -> stenoxide_core::crypto::expand::DerivedKeys {
    let image = load_and_validate(container).expect("the container must validate");
    let salt = compute_stable_phash(&image).expect("the container must hash");
    let master_key = Argon2Kdf::low_cost_for_tests()
        .derive(password, &salt)
        .expect("a non-empty password must stretch");

    expand_master_key(&master_key).expect("expansion must succeed")
}

/// TEST 1 — a generated container gives its message back.
#[test]
fn a_generated_container_round_trips() {
    let (plaintext, report) = test_pipeline()
        .extract(shared_container(), secret(PASSWORD))
        .expect("the right password must recover the payload");

    assert_eq!(plaintext.as_slice(), MESSAGE);

    // The ciphertext is the whole container, whatever it carries. That is what
    // keeps the size of the message from leaking, and it is why this figure is
    // a constant rather than a measurement of the payload.
    assert_eq!(report.payload_bytes, 1_500_000);
}

/// TEST 2 — an empty payload is a payload.
///
/// The degenerate end of the range. Nothing about the container changes: it is
/// the same size, drawn the same way, and indistinguishable from one carrying a
/// megabyte.
#[test]
fn an_empty_payload_round_trips() {
    let container = generate("generated_empty.png", b"");

    let (plaintext, _report) = test_pipeline()
        .extract(&container, secret(PASSWORD))
        .expect("the right password must recover an empty payload");

    assert!(plaintext.is_empty());
}

/// TEST 3 — the payload size that matters, near the capacity of a container.
///
/// The 0.02 bpp cap does not apply to this mode, and this is what that means in
/// bytes: a 2000x2000 container carries 1.45 MB where the embedding path
/// carries about 7 KB. The payload is incompressible, so it is really that
/// large after Zstandard rather than before it.
#[test]
fn a_payload_near_the_capacity_round_trips() {
    let payload = support::incompressible_payload(NEAR_CAPACITY_BYTES);
    let container = generate("generated_full.png", &payload);

    let (plaintext, _report) = test_pipeline()
        .extract(&container, secret(PASSWORD))
        .expect("a payload just under the capacity must round trip");

    assert_eq!(plaintext.len(), NEAR_CAPACITY_BYTES);
    assert_eq!(plaintext.as_slice(), payload.as_slice());
}

/// TEST 3b — a larger, rectangular container carries what a default one cannot.
///
/// The whole point of the size being a parameter, end to end: a payload just
/// over what a 2000x2000 container admits (`1_499_980` bytes) is refused by the
/// default and accepted by a rectangular container of greater area — which then
/// round-trips through the ordinary extraction path like any other. It also
/// exercises the anisotropic texture: a non-square container has to clear the
/// same hash, cost and block gates a square one does, and this is the only test
/// that renders one at full size.
#[test]
fn a_larger_rectangular_container_carries_a_bigger_payload() {
    // 2400x2000 admits 1_799_980 compressed bytes, so an incompressible payload
    // that overflows the default by a comfortable margin still fits here.
    let dimensions = ContainerDimensions::new(2400, 2000).expect("within the permitted range");
    let payload = support::incompressible_payload(1_550_000);

    let container = generate_sized("generated_rectangular.png", &payload, dimensions);

    let image = load_and_validate(&container).expect("a larger container must still validate");
    assert_eq!(image.dimensions(), (2400, 2000));

    let (plaintext, _report) = test_pipeline()
        .extract(&container, secret(PASSWORD))
        .expect("a payload that only fits the larger container must round trip");

    assert_eq!(plaintext.len(), payload.len());
    assert_eq!(plaintext.as_slice(), payload.as_slice());
}

/// TEST 4 — a generated container passes every gate a receiver applies.
///
/// The circularity is untied by the perceptual hash surviving the second
/// render, so a container whose hash had moved would be unreadable rather than
/// merely odd. The other two gates are what make it an ordinary container: the
/// loader has to accept it, and the block detector must not read a JPEG grid in
/// a texture drawn at a 62.5-pixel scale.
#[test]
fn a_generated_container_passes_the_gates_of_layer_one() {
    let image = load_and_validate(shared_container()).expect("a generated container must validate");

    let (width, height) = image.dimensions();
    assert_eq!((width, height), (2000, 2000));

    assert_eq!(
        detect_jpeg_artifacts(image.pixels(), width, height, image.color_space()),
        None,
        "a generated container must not read as previously JPEG-compressed"
    );

    assert!(
        compute_stable_phash(&image).is_ok(),
        "a generated container must hash reproducibly, which is what its own key was derived from"
    );
}

/// TEST 5 — `scan` accepts a generated container.
///
/// The checks `stenoxide scan` runs, in the order it runs them. The capacity it
/// reports is around 8.3 KB, which looks like a bug and is not: that is the
/// *embedding* capacity of an image of this size, the figure that answers "how
/// much could be hidden inside this". The container is already holding far more
/// than that by having been generated around it, and no property of the file
/// says so — which is the whole point.
#[test]
fn scan_accepts_a_generated_container() {
    let image = load_and_validate(shared_container()).expect("a generated container must validate");

    assert!(compute_stable_phash(&image).is_ok());

    let cost_map = HillCostProvider::new()
        .compute(&image)
        .expect("a generated container must have texture the cost model accepts");
    let capacity = compute_capacity(&cost_map, EmbeddingMode::Symmetric).available_bytes();

    assert!(
        capacity > 4_000,
        "scan must report a usable embedding capacity, got {capacity}"
    );
}

/// TEST 6 — a wrong password fails identically on both kinds of container.
///
/// The property that keeps `extract` from becoming an oracle for which
/// construction produced an image. An attacker with a candidate password learns
/// the same sentence either way, and the test compares the two rather than
/// asserting a literal, which is what stops them from drifting apart later.
#[test]
fn a_wrong_password_fails_alike_on_both_kinds_of_container() {
    let embedded = support::fixtures_dir().join("generated_comparison_stego.png");
    test_pipeline()
        .embed(
            &support::textured_cover(),
            secret(MESSAGE),
            secret(PASSWORD),
            &embedded,
        )
        .expect("embedding into the textured cover must succeed");

    // Discarding the success value keeps a recovered plaintext out of the panic
    // message, in the one case where these assertions firing would mean the
    // wrong password had worked.
    let on_embedded = test_pipeline()
        .extract(&embedded, secret(WRONG_PASSWORD))
        .map(|_| ())
        .expect_err("the wrong password must fail on an embedded container");

    let on_generated = test_pipeline()
        .extract(shared_container(), secret(WRONG_PASSWORD))
        .map(|_| ())
        .expect_err("the wrong password must fail on a generated container");

    assert_eq!(
        on_generated.to_string(),
        on_embedded.to_string(),
        "the two constructions must fail with one sentence"
    );
    assert_eq!(
        format!("{on_generated:?}"),
        format!("{on_embedded:?}"),
        "and with one error value, so that a caller matching on it cannot tell them apart either"
    );

    let _ = std::fs::remove_file(&embedded);
}

/// TEST 7 — two generations share nothing, message and password included.
///
/// Two properties in one pair of containers, because they have one cause.
///
/// The rule "one image + one password = one message" is a matter of the user's
/// discipline for the embedding path and is satisfied by construction here:
/// each generation is a different container, so it hashes differently, so the
/// salt, the key and the nonce all differ. Nothing has to be remembered for
/// that to hold.
///
/// And it is a test that the generator is *not* reproducible. The seed comes
/// from the system CSPRNG, so the same inputs must produce different files —
/// a test demanding determinism here would be demanding the one failure that
/// matters, because a container an adversary can regenerate is one they can
/// compare against.
#[test]
fn two_generations_share_neither_their_samples_nor_their_keys() {
    let first = std::fs::read(shared_container()).expect("the container must be readable");
    let second = std::fs::read(twin_container()).expect("the container must be readable");

    assert_ne!(
        first, second,
        "two generations of one message under one password must not agree"
    );

    let first_keys = derived_keys(shared_container(), PASSWORD);
    let second_keys = derived_keys(twin_container(), PASSWORD);

    assert_ne!(
        first_keys.enc_key(),
        second_keys.enc_key(),
        "a different container must derive a different key"
    );
    assert_ne!(
        first_keys.nonce(),
        second_keys.nonce(),
        "and a different nonce, which is what makes the reuse rule unbreakable here"
    );

    // Each is still readable under the password they share: different keys are
    // not a failure of the mode, they are the mode working.
    let (plaintext, _report) = test_pipeline()
        .extract(twin_container(), secret(PASSWORD))
        .expect("the second container must round trip on its own key");
    assert_eq!(plaintext.as_slice(), MESSAGE);
}
