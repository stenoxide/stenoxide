//! Writes the seed corpus the three targets start from.
//!
//! # Why a campaign must not start empty
//!
//! A fuzzer given nothing spends its budget rediscovering the shape of the
//! input. For T1 and T2 that shape is the PNG format: eight bytes of signature,
//! a chunk length, a chunk type, a geometry above 2000x2000, a deflate stream
//! that decodes, and no JPEG blocking grid — found by mutation alone, that is
//! the whole campaign, and it ends with a corpus of files that were all refused
//! at the first gate. Seeded with one container the crate accepts, the fuzzer
//! starts on the far side of every gate and spends its budget on what happens
//! after them.
//!
//! T3 is the same argument one layer down: seeded with a real Zstandard frame,
//! the mutations are mutations *of a frame* rather than of random bytes that
//! the decoder rejects in its first four.
//!
//! # This is not a fuzz target
//!
//! It links no libFuzzer, needs no nightly toolchain and runs anywhere the
//! workspace builds:
//!
//! ```text
//! cargo run --release --bin seed_corpus
//! ```
//!
//! Release matters. The container is a 2000x2000 image drawn a pixel at a time
//! and then judged by the perceptual-hash and texture gates, and the stego seed
//! runs a whole embedding on top; unoptimised that is minutes rather than
//! seconds.

use std::path::Path;

use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::crypto::aead::XChaCha20Poly1305Cipher;
use stenoxide_core::crypto::kdf::Argon2Kdf;
use stenoxide_core::pipeline::EmbedPipeline;
use stenoxide_core::test_support;
use zeroize::Zeroizing;

/// Seed the container search starts from.
///
/// The one the integration suite uses. It passes on its first candidate, so the
/// seeder does not pay for a search.
const COVER_SEED: u64 = 337;

/// The message hidden inside the stego seed of T2.
const SEED_MESSAGE: &[u8] = b"a message the extraction target can actually find";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let loader_corpus = stenoxide_fuzz::corpus_dir("loader");
    let extract_corpus = stenoxide_fuzz::corpus_dir("extract");
    let decompress_corpus = stenoxide_fuzz::corpus_dir("decompress");

    for directory in [&loader_corpus, &extract_corpus, &decompress_corpus] {
        std::fs::create_dir_all(directory)?;
    }

    // A container that clears every gate of layer 1. This is the seed that
    // matters most: it is the only one of the three the fuzzer would have had
    // to invent from nothing.
    let cover = loader_corpus.join("valid_cover.png");
    test_support::write_stable_cover(&cover, COVER_SEED);
    report(&cover)?;

    // Small files that fail at three different gates, so the fuzzer starts with
    // the shape of a refusal as well as the shape of an acceptance.
    write(&loader_corpus.join("png_signature_only.bin"), &png_stub())?;
    write(&loader_corpus.join("jpeg_signature.bin"), &[0xFF, 0xD8, 0xFF, 0xE0])?;
    write(&loader_corpus.join("empty.bin"), &[])?;

    // T2 wants a container the extraction path gets all the way through, not
    // merely one it loads. Embedding under the target's own password is the
    // only way to produce one.
    let stego = extract_corpus.join("stego_under_the_fuzz_password.png");
    EmbedPipeline::new(
        Argon2Kdf::low_cost_for_tests(),
        XChaCha20Poly1305Cipher::new(),
        HillCostProvider::new(),
    )
    .embed(
        &cover,
        Zeroizing::new(SEED_MESSAGE.to_vec()),
        Zeroizing::new(stenoxide_fuzz::FUZZ_PASSWORD.to_vec()),
        &stego,
    )?;
    report(&stego)?;

    // And the plain container beside it: an image that loads and carries
    // nothing is the other half of what T2 has to survive.
    std::fs::copy(&cover, extract_corpus.join("valid_cover.png"))?;

    // T3 is fed the plaintext that will be sealed, so its seeds are Zstandard
    // frames: one ordinary, one that expands far past its own size.
    write(
        &decompress_corpus.join("ordinary_frame.zst"),
        &zstd::encode_all(SEED_MESSAGE, 19)?,
    )?;
    write(
        &decompress_corpus.join("expanding_frame.zst"),
        &zstd::encode_all(vec![0u8; 8 * 1024 * 1024].as_slice(), 19)?,
    )?;

    Ok(())
}

/// The eight PNG signature bytes and nothing behind them.
///
/// The file the format gate accepts and the chunk check immediately refuses,
/// which is a boundary worth handing the fuzzer rather than making it find.
fn png_stub() -> Vec<u8> {
    vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
}

/// Writes one corpus entry and says so.
fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(path, bytes)?;
    report(path)
}

/// Prints what was written and how large it is.
fn report(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("{} ({} bytes)", path.display(), std::fs::metadata(path)?.len());
    Ok(())
}
