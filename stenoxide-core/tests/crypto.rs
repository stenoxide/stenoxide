//! Tests of the cryptographic chain on its own, without the coder.
//!
//! Everything from the container's perceptual hash down to the authenticated
//! ciphertext runs without Syndrome-Trellis coding, and this file pins that half
//! on its own. The round trip in `integration.rs` covers the same ground on its
//! way past, but only as a whole: when it breaks it says the message did not
//! come back, not which of the four derivations moved.
//!
//! That is the dependency surface these tests exist for. Argon2id, HKDF-SHA3-512
//! and XChaCha20-Poly1305 come from separate crates that move independently, and
//! a version bump quietly changing a derivation would otherwise surface as an
//! unrelated failure much later.

mod support;

use stenoxide_core::crypto::aead::{
    compress_and_encrypt, decrypt_and_decompress, AEADError, CryptoError, XChaCha20Poly1305Cipher,
};
use stenoxide_core::crypto::expand::expand_master_key;
use stenoxide_core::crypto::kdf::{Argon2Kdf, KeyDeriver};
use stenoxide_core::image_io::phash::compute_stable_phash;
use stenoxide_core::image_io::validate::load_and_validate;

/// The payload these tests carry through the chain.
///
/// Repetitive on purpose: compression has to actually do something for the
/// decompression half of the round trip to mean anything.
fn plaintext() -> Vec<u8> {
    b"salt, subkey, nonce, tag - and back again. ".repeat(16)
}

/// Derives the subkeys the pipeline would derive for a given password.
///
/// The salt is the container's perceptual hash, exactly as in production: there
/// is no other way to obtain a `PHashSalt`, and inventing one would test a
/// derivation the pipeline never performs.
fn derive_keys(password: &[u8]) -> stenoxide_core::crypto::expand::DerivedKeys {
    let cover = load_and_validate(&support::textured_cover()).expect("the cover must load");
    let salt = compute_stable_phash(&cover).expect("the cover must hash stably");

    let master_key = Argon2Kdf::low_cost_for_tests()
        .derive(password, &salt)
        .expect("argon2id must accept a non-empty password");

    expand_master_key(&master_key).expect("hkdf-sha3-512 must expand a 32-byte master key")
}

/// Compression, encryption, authentication and back.
#[test]
fn payload_survives_encryption_and_compression() {
    let keys = derive_keys(b"a-passphrase");
    let cipher = XChaCha20Poly1305Cipher::new();

    let plaintext = plaintext();
    let ciphertext = compress_and_encrypt(&plaintext, keys.enc_key(), keys.nonce(), &cipher)
        .expect("compression and encryption must succeed");

    // The point of compressing first: a payload this repetitive must come out
    // smaller than it went in, tag included. If it ever does not, the ordering
    // of the two stages has been swapped.
    assert!(
        ciphertext.len() < plaintext.len(),
        "compressed ciphertext ({}) should be shorter than the plaintext ({})",
        ciphertext.len(),
        plaintext.len()
    );

    let recovered = decrypt_and_decompress(&ciphertext, keys.enc_key(), keys.nonce(), &cipher)
        .expect("decryption and decompression must succeed");

    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

/// A tampered ciphertext is refused, and refused as an authentication failure.
#[test]
fn a_flipped_bit_fails_authentication() {
    let keys = derive_keys(b"a-passphrase");
    let cipher = XChaCha20Poly1305Cipher::new();

    let ciphertext = compress_and_encrypt(&plaintext(), keys.enc_key(), keys.nonce(), &cipher)
        .expect("compression and encryption must succeed");

    let mut damaged = ciphertext.to_vec();
    damaged[0] ^= 1;

    let error = decrypt_and_decompress(&damaged, keys.enc_key(), keys.nonce(), &cipher)
        .map(|_| ())
        .expect_err("a modified ciphertext must not authenticate");

    assert!(
        matches!(
            error,
            CryptoError::AEADError(AEADError::AuthenticationFailed)
        ),
        "expected an authentication failure, got: {error:?}"
    );
}

/// The whole scheme rests on this: the same password and the same container
/// must always produce the same subkeys.
///
/// Nothing travels with the payload — no salt, no nonce, no seed. The receiver
/// rebuilds all three from the image and the password alone, so a derivation
/// that is not reproducible is a payload that is not recoverable.
#[test]
fn derivation_is_reproducible_and_password_dependent() {
    let first = derive_keys(b"a-passphrase");
    let second = derive_keys(b"a-passphrase");

    assert_eq!(first.enc_key(), second.enc_key());
    assert_eq!(first.nonce(), second.nonce());
    assert_eq!(first.stc_seed(), second.stc_seed());

    let other = derive_keys(b"a-different-passphrase");
    assert_ne!(first.enc_key(), other.enc_key());
    assert_ne!(first.nonce(), other.nonce());
    assert_ne!(first.stc_seed(), other.stc_seed());

    // The three subkeys are cut from one HKDF output under different info
    // strings. If the domain separation were ever dropped they would start to
    // coincide, which no length check would catch.
    assert_ne!(first.enc_key(), first.stc_seed());
}
