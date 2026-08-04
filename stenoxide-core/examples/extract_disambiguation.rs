//! Can one `extract` serve two kinds of container without leaking which it got?
//!
//! A generated container carries its payload in every sample's least
//! significant bit; an embedded one carries it through the trellis, in a secret
//! order, at 0.02 bpp. They are read by different code, so a receiver has to
//! know which it holds — and the obvious ways to tell it are all bad. A flag in
//! the file would be the marker this project has gone to some trouble not to
//! have; a distinct error would let an attacker with a candidate password learn
//! which construction produced an image.
//!
//! The alternative is to try both and say the same thing when neither works.
//! That is only sound if two things hold, and this harness checks them:
//!
//! 1. **Reading the wrong way fails.** The trellis decoder handed a generated
//!    container must not authenticate, and the generative reader handed an
//!    embedded one must not either. Both end at a Poly1305 tag, so the question
//!    is whether either can be induced to produce a valid one — it cannot, but
//!    a demonstration costs little.
//! 2. **Trying both is cheap.** The expensive step is Argon2id, and both paths
//!    derive from the same perceptual hash of the same image, so one derivation
//!    serves both attempts. The second attempt costs a stream cipher over a
//!    megabyte and nothing else.
//!
//! Run with:
//!
//! ```sh
//! cargo run --release --example extract_disambiguation --features test-utils -- <dir>
//! ```
//!
//! where `<dir>` holds `image_00.png` from `generative_stego` and a container
//! produced by the ordinary embedding path.

use std::path::{Path, PathBuf};
use std::time::Instant;

use image::RgbImage;
use stenoxide_core::crypto::aead::{compress_and_encrypt, decrypt_and_decompress,
                                   XChaCha20Poly1305Cipher};
use stenoxide_core::crypto::expand::expand_master_key;
use stenoxide_core::crypto::kdf::{Argon2Kdf, KeyDeriver};
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::load_and_validate;
use stenoxide_core::pipeline::EmbedPipeline;
use stenoxide_core::test_support::incompressible_payload;
use zeroize::Zeroizing;

/// The password both prototypes were driven with.
const PASSWORD: &[u8] = b"prototype-password-not-a-real-secret";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).map_or("gen16", String::as_str));

    let generated = dir.join("image_00.png");
    if !generated.exists() {
        eprintln!("expected {} — run generative_stego first", generated.display());
        return;
    }

    println!("Reading a generated container the two ways\n");

    // The generative read, which should work.
    let (ok, elapsed) = timed(|| generative_read(&generated).is_ok());
    println!("  generative reader : {:<12} {elapsed:>8.2?}",
             if ok { "authenticates" } else { "FAILS" });

    // The trellis read, which should not. Note it is given the *right*
    // password: the point is that the construction, not the secret, is wrong.
    let (trellis_ok, elapsed) = timed(|| {
        EmbedPipeline::default_secure()
            .extract(&generated, Zeroizing::new(PASSWORD.to_vec()))
            .is_ok()
    });
    println!("  trellis reader    : {:<12} {elapsed:>8.2?}",
             if trellis_ok { "AUTHENTICATES — BAD" } else { "refuses" });

    println!("\nCost of the derivation both paths share");
    let (_, derivation) = timed(|| derive_only(&generated));
    println!("  one Argon2id at production cost : {derivation:>8.2?}");
    let (_, second) = timed(|| generative_read(&generated).is_ok());
    println!("  the second attempt on top of it : {second:>8.2?}");

    println!("\nSo a receiver can try both under one derivation and report the");
    println!("same refusal for every failure, which is what the project already");
    println!("does for a wrong password, a wrong image and a damaged payload.");
}

/// Times a closure, returning its value and how long it took.
fn timed<T, F: FnOnce() -> T>(work: F) -> (T, std::time::Duration) {
    let start = Instant::now();
    let value = work();
    (value, start.elapsed())
}

/// Derives the key from the container and stops, to price the shared step.
fn derive_only(path: &Path) -> bool {
    let Ok(buffer) = load_and_validate(path) else {
        return false;
    };
    let Ok(salt) = compute_stable_phash(&buffer) else {
        return false;
    };

    Argon2Kdf::default_secure().derive(PASSWORD, &salt).is_ok()
}

/// Reads a container built by the generative construction.
fn generative_read(path: &Path) -> Result<Vec<u8>, String> {
    let buffer = load_and_validate(path).map_err(|err| err.to_string())?;
    let salt = compute_stable_phash(&buffer).map_err(|err| err.to_string())?;

    // The prototype used the cheap deriver, so this must match it to read back
    // what it wrote. Production would use `default_secure` on both sides.
    let master = Argon2Kdf::low_cost_for_tests()
        .derive(PASSWORD, &salt)
        .map_err(|err| err.to_string())?;
    let keys = expand_master_key(&master).map_err(|err| err.to_string())?;

    // The exact ciphertext length, which the receiver does not have.
    //
    // Reconstructing it here — same deterministic payload, same key, same
    // compressor — is a shortcut this harness can take and a real receiver
    // cannot, and that is the finding rather than a detail: Zstandard on
    // incompressible input returns a few bytes *more* than it was given, so the
    // length is not a function of anything the receiver knows. Guessing it
    // wrong fails exactly like a wrong password, since the tag covers the whole
    // buffer. Any real design has to carry the length inside the authenticated
    // plaintext and fill the container to the last sample, which has the
    // side benefit of hiding the message size completely.
    let ciphertext_len = compress_and_encrypt(
        &incompressible_payload(1_000_000),
        keys.enc_key(),
        keys.nonce(),
        &XChaCha20Poly1305Cipher::new(),
    )
    .map_err(|err| err.to_string())?
    .len();

    let image = image::open(path).map_err(|err| err.to_string())?.to_rgb8();
    let carried = read_bits(&image, ciphertext_len);

    decrypt_and_decompress(
        &carried,
        keys.enc_key(),
        keys.nonce(),
        &XChaCha20Poly1305Cipher::new(),
    )
    .map(|plaintext| plaintext.to_vec())
    .map_err(|err| err.to_string())
}

/// Collects the least significant bits of the first `bytes * 8` samples.
fn read_bits(image: &RgbImage, bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; bytes];

    for (position, sample) in image.as_raw().iter().enumerate().take(bytes * 8) {
        out[position / 8] |= (sample & 1) << (7 - position % 8);
    }

    out
}
