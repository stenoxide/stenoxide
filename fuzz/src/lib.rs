//! What the three fuzz targets share.
//!
//! Every target is its own binary, so anything two of them agree on has to live
//! somewhere both can see. That is three things: the scratch file the loader
//! and the extraction target hand their bytes to, the fixed secrets the
//! extraction and decompression targets run under, and the associated data the
//! crate binds into every tag.
//!
//! Nothing here is a fuzz target. `cargo fuzz` never builds this on its own; it
//! is linked into the binaries that do.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tempfile::TempDir;

/// The password every extraction attempt runs under.
///
/// Fixed rather than fuzzed. The interesting input is the *container*: a
/// password is stretched through Argon2id into 32 bytes that the attacker
/// cannot steer, so mutating it explores nothing the container does not already
/// cover, and it would double the derivations a campaign pays for.
pub const FUZZ_PASSWORD: &[u8] = b"fuzzing-passphrase";

/// The key the decompression target seals its input under.
///
/// It stands for the key a malicious *sender* holds. Decompression happens only
/// after the Poly1305 tag has verified, so the input that reaches the
/// decompressor is by definition input somebody with the key chose — and that
/// is exactly the position this target puts the fuzzer in.
pub const SENDER_KEY: [u8; 32] = [0x2Bu8; 32];

/// The nonce that goes with [`SENDER_KEY`].
pub const SENDER_NONCE: [u8; 24] = [0x7Fu8; 24];

/// The associated data `stenoxide` binds into every tag.
///
/// A copy of `crypto::aead::STENOXIDE_AAD`, which is `pub(crate)` and therefore
/// invisible from out here. The copy is not left to trust: the decompression
/// target checks on its first execution that a buffer sealed under this string
/// opens again through the crate's own entry point, and aborts if it does not.
/// A silently wrong value would turn that target into one that only ever
/// measures how the AEAD rejects things.
pub const STENOXIDE_AAD: &[u8] = b"STENOXIDE-v1";

/// The directory the scratch container lives in, for the life of the process.
static SCRATCH: OnceLock<TempDir> = OnceLock::new();

/// Writes `bytes` to a scratch file and returns the path to it.
///
/// The two image targets need one, because the only public way into the loader
/// takes a path: a container arrives as a file and the crate reads it itself.
/// The file is created once per process and rewritten on every execution, so a
/// campaign of a million cases costs a million writes and one create.
///
/// Returns `None` when the write fails, which is a fact about the machine
/// running the campaign and not about the input; the caller skips that
/// execution rather than reporting a finding.
pub fn write_scratch(bytes: &[u8]) -> Option<PathBuf> {
    let directory = SCRATCH.get_or_init(|| {
        tempfile::tempdir().expect("a fuzzing host must provide a temporary directory")
    });

    let path = directory.path().join("candidate.png");
    std::fs::write(&path, bytes).ok()?;

    Some(path)
}

/// Where the seeded corpus for `target` lives, relative to this crate.
///
/// One place that spells the layout `cargo fuzz` expects, so the seeder writes
/// where the runner reads.
pub fn corpus_dir(target: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus").join(target)
}
