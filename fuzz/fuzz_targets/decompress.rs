//! T3 — arbitrary *authenticated* content against the decompressor.
//!
//! The other two targets stand where an eavesdropper stands. This one stands
//! where the sender stands, and that is the point: decompression happens only
//! after the Poly1305 tag has verified, so nothing reaches the Zstandard
//! decoder unless somebody holding the key put it there. A stranger cannot get
//! this far. A correspondent can, and a correspondent is not automatically a
//! friend — nor is whoever encrypts against a public key of yours, the day that
//! mode exists.
//!
//! So the target seals the fuzzer's bytes under a known key and hands them to
//! `decrypt_and_decompress`, which is exactly the shape of the attack: the
//! attacker controls the plaintext that the decompressor sees, in full, and
//! nothing in between gets to object.
//!
//! # The invariant
//!
//! Never a panic, and never an allocation out of proportion to the input.
//! The second half is what this target was written for. Zstandard is a
//! compression format, not a container format: a frame declares how far it
//! expands and the decoder obliges, so a ciphertext that fits in a 1.45 MB
//! generated container can ask for tens of gigabytes. Before the ceiling in
//! `crypto::aead` existed, a campaign here was expected to end with the machine
//! swapping rather than with a report — which is a finding, just not one
//! libFuzzer is good at phrasing. With the ceiling in place the same input
//! comes back as an error, and `-rss_limit_mb` is what says so.

#![no_main]

use libfuzzer_sys::fuzz_target;
use stenoxide_core::crypto::aead::{
    decrypt_and_decompress, AEADCipher, XChaCha20Poly1305Cipher,
};

/// Runs the canary exactly once per process.
static CANARY: std::sync::Once = std::sync::Once::new();

/// Proves that a buffer sealed the way this target seals one really does open
/// through the crate's own entry point.
///
/// The associated data is a copy of a `pub(crate)` constant, so it is checked
/// rather than trusted. A wrong copy would make every seal below fail to open,
/// and the target would spend an entire campaign measuring how the AEAD rejects
/// things instead of how the decompressor handles them — a green run that meant
/// nothing at all.
fn check_the_canary(cipher: &XChaCha20Poly1305Cipher) {
    const CANARY_PAYLOAD: &[u8] = b"a canary payload";

    let frame = zstd::encode_all(CANARY_PAYLOAD, 19).expect("zstandard must compress the canary");
    let sealed = cipher
        .encrypt(
            &stenoxide_fuzz::SENDER_KEY,
            &stenoxide_fuzz::SENDER_NONCE,
            &frame,
            stenoxide_fuzz::STENOXIDE_AAD,
        )
        .expect("the cipher must seal the canary");

    let opened = decrypt_and_decompress(
        &sealed,
        &stenoxide_fuzz::SENDER_KEY,
        &stenoxide_fuzz::SENDER_NONCE,
        cipher,
    )
    .expect("the canary must open: the associated data copy is wrong");

    assert_eq!(
        opened.as_slice(),
        CANARY_PAYLOAD,
        "the canary opened to something else"
    );
}

fuzz_target!(|data: &[u8]| {
    let cipher = XChaCha20Poly1305Cipher::new();
    CANARY.call_once(|| check_the_canary(&cipher));

    let Ok(sealed) = cipher.encrypt(
        &stenoxide_fuzz::SENDER_KEY,
        &stenoxide_fuzz::SENDER_NONCE,
        data,
        stenoxide_fuzz::STENOXIDE_AAD,
    ) else {
        return;
    };

    // Whatever the fuzzer wrote is now authenticated content. Everything that
    // happens from here is the decompressor's answer to a sender who meant it.
    let _ = decrypt_and_decompress(
        &sealed,
        &stenoxide_fuzz::SENDER_KEY,
        &stenoxide_fuzz::SENDER_NONCE,
        &cipher,
    );
});
