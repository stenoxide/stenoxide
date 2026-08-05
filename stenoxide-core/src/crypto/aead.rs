//! XChaCha20-Poly1305 authenticated encryption of the payload.
//!
//! The payload is compressed before it is encrypted, never the other way round:
//! ciphertext is indistinguishable from random and therefore incompressible, so
//! compressing afterwards would cost time and save nothing. Compressing first
//! also shrinks what has to be embedded, which directly lowers the bits per
//! pixel the embedding layer needs — the single most important factor in
//! staying invisible to steganalysis.

use std::fmt;
use std::io::Read;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

/// Associated data bound into every tag produced by this crate.
///
/// It is not secret and not transmitted: both sides recompute it. Its purpose
/// is to make a ciphertext produced by `stenoxide` fail authentication if it is
/// ever fed to a different XChaCha20-Poly1305 construction, and vice versa.
///
/// Readable inside the crate because [`crate::generate`] seals a buffer that is
/// not simply `zstd(message)` and therefore cannot go through
/// [`compress_and_encrypt`] — but must be bound to the same construction, so
/// that one associated string covers everything this crate encrypts.
pub(crate) const STENOXIDE_AAD: &[u8] = b"STENOXIDE-v1";

/// Associated data bound into the tag of a passphrase-protected private key
/// file.
///
/// A second string rather than [`STENOXIDE_AAD`] because the two protect
/// different things under keys derived the same way: one is a payload hidden in
/// a container, the other is a key file sitting on the owner's disk. Binding
/// them apart means a container's ciphertext handed to the key-file reader — or
/// the reverse — fails authentication instead of being decrypted into
/// something that has to be judged afterwards.
#[cfg(feature = "pqc")]
pub(crate) const STENOXIDE_IDENTITY_AAD: &[u8] = b"STENOXIDE-identity-v1";

/// Zstandard compression level. The maximum non-ultra level: the payload is
/// small and compressed exactly once, so spending time here is free compared
/// with the embedding capacity it buys back.
const ZSTD_LEVEL: i32 = 19;

/// Largest plaintext one authenticated payload is allowed to expand to.
///
/// # Why a ceiling exists at all
///
/// Zstandard is a compression format, not a container format: a frame says how
/// much it expands to and the decoder obliges. A few kilobytes of ciphertext
/// can therefore ask for terabytes of memory, and an unbounded
/// [`decompress`] would hand that request straight to the allocator.
///
/// Authentication runs first, so a stranger never reaches this code — but the
/// threat is not a stranger. The sender is whoever holds the key, and holding
/// the key is not the same as being a friend. A correspondent can build a frame
/// that fits inside a container the receiver accepts and expands to more memory
/// than the receiver has. With the embedding path the damage is bounded by a
/// capacity of a few kilobytes; with [`crate::generate`], where the default
/// container carries 1.45 MB and every sample is free, a valid container can
/// ask for tens of gigabytes. This constant is what turns that request into an
/// error instead.
///
/// # Where the number comes from
///
/// The bound is a property of the system rather than a guess. The largest
/// payload this crate can *produce* is limited by the container that carries
/// it: the generative mode fills every sample, so at the `MAX_PIXELS` ceiling
/// of layer 1 — 128 Mi pixels over three channels, one bit each — the largest
/// ciphertext that can exist is 48 MiB, the default 2000x2000 container carries
/// 1.45 MB, and the embedding path carries some 7 KB. Half a gibibyte is
/// therefore a tenfold expansion of the largest container this system will draw
/// and roughly three hundredfold of the ordinary one, which is far past any
/// compression ratio a payload worth hiding reaches.
///
/// From the other side it stays well under what a machine can spare: layer 1
/// already commits to a peak working set of about two gibibytes when it accepts
/// a maximum-size container, so the ceiling does not raise the memory profile
/// the program already has. The rounding to a power of two is arbitrary and
/// admitted as such; the order of magnitude is not.
const MAX_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Failures of the authenticated encryption primitive.
#[derive(Debug)]
pub enum AEADError {
    /// The ciphertext did not authenticate.
    ///
    /// A wrong key, a wrong nonce, a modified tag and a truncated ciphertext
    /// all collapse into this one variant on purpose; see
    /// [`AEADCipher::decrypt`].
    AuthenticationFailed,
    /// The cipher failed while encrypting.
    CipherError(String),
}

impl fmt::Display for AEADError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AEADError::AuthenticationFailed => {
                write!(f, "authentication failed: wrong password or corrupted data")
            }
            AEADError::CipherError(message) => write!(f, "cipher error: {message}"),
        }
    }
}

impl std::error::Error for AEADError {}

/// Failures of the combined compression and encryption stages.
#[derive(Debug)]
pub enum CryptoError {
    /// Zstandard could not compress the plaintext.
    CompressionError(String),
    /// Zstandard could not decompress the authenticated plaintext.
    DecompressionError(String),
    /// The authenticated encryption layer failed.
    AEADError(AEADError),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::CompressionError(message) => {
                write!(f, "failed to compress the payload: {message}")
            }
            CryptoError::DecompressionError(message) => {
                write!(f, "failed to decompress the payload: {message}")
            }
            CryptoError::AEADError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CryptoError::AEADError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<AEADError> for CryptoError {
    fn from(err: AEADError) -> Self {
        CryptoError::AEADError(err)
    }
}

/// Authenticated encryption with associated data.
///
/// Abstracted behind a trait so the pipeline depends on the operation and not
/// on the concrete cipher. `Send + Sync` because a single cipher value is
/// shared by reference across the pipeline's worker threads.
pub trait AEADCipher: Send + Sync {
    /// Encrypts `plaintext` under `key` and `nonce`, binding `aad` to the tag.
    ///
    /// The returned buffer is the ciphertext with the 16-byte Poly1305 tag
    /// appended, and it is wiped when dropped.
    ///
    /// # Errors
    ///
    /// Returns [`AEADError::CipherError`] if the underlying cipher fails.
    fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AEADError>;

    /// Decrypts and authenticates `ciphertext`, which must carry its trailing
    /// tag and must have been produced with the same `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`AEADError::AuthenticationFailed`], and nothing else. Every
    /// internal cause — invalid tag, wrong key, truncated input — is collapsed
    /// into that single variant, because distinguishing them would hand an
    /// attacker an oracle that tells them *why* their guess was rejected.
    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AEADError>;
}

/// The production cipher: XChaCha20-Poly1305.
///
/// The 192-bit extended nonce is what makes the derived — rather than random —
/// nonce of [`crate::crypto::expand`] safe: the space is far too large for the
/// birthday bound to matter.
#[derive(Debug, Default, Clone, Copy)]
pub struct XChaCha20Poly1305Cipher;

impl XChaCha20Poly1305Cipher {
    /// Builds the cipher. It is stateless; the key arrives per call.
    pub fn new() -> Self {
        Self
    }
}

impl AEADCipher for XChaCha20Poly1305Cipher {
    fn encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AEADError> {
        let cipher = XChaCha20Poly1305::new(key.into());
        // The crate appends the 16-byte Poly1305 tag to the ciphertext itself,
        // so there is no tag to carry or splice by hand on either side.
        let ciphertext = cipher
            .encrypt(
                nonce.into(),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|err| AEADError::CipherError(err.to_string()))?;

        Ok(Zeroizing::new(ciphertext))
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, AEADError> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let plaintext = cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            // The inner error is discarded deliberately: it is the only place
            // where the failure reason could leak out of this layer.
            .map_err(|_| AEADError::AuthenticationFailed)?;

        Ok(Zeroizing::new(plaintext))
    }
}

/// Compresses `plaintext` with Zstandard, at the one level this crate uses.
///
/// Split out of [`compress_and_encrypt`] because the generative container mode
/// compresses at the same level and then seals the result inside a larger
/// buffer of its own; the compression level is a property of the format both
/// share, and there is one definition of it.
///
/// # Errors
///
/// Returns [`CryptoError::CompressionError`] if Zstandard fails.
pub(crate) fn compress(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    zstd::encode_all(plaintext, ZSTD_LEVEL)
        .map(Zeroizing::new)
        .map_err(|err| CryptoError::CompressionError(err.to_string()))
}

/// Decompresses an authenticated Zstandard frame, up to a fixed ceiling.
///
/// The inverse of [`compress`]. Nothing must reach this that the Poly1305 tag
/// has not already vouched for; both callers arrange that.
///
/// The output is bounded by [`MAX_DECOMPRESSED_BYTES`], and it is bounded while
/// the frame is being read rather than checked afterwards: the decoder is a
/// stream and the read stops one byte past the ceiling, so a frame that expands
/// without limit never gets to allocate without limit. Reading that one extra
/// byte is what separates a payload that ends exactly at the ceiling, which is
/// allowed, from one that does not, which is not.
///
/// # Why the failure is not its own error variant
///
/// A payload over the ceiling is reported as [`CryptoError::DecompressionError`],
/// the same variant a payload that is not a Zstandard frame at all comes back
/// as. Only the sentence inside it differs, which means no caller can branch on
/// "compression bomb" against "damaged payload" without matching on a string.
///
/// The oracle argument that forces one single sentence on the extraction
/// surface does not really apply here — decompression happens after the tag has
/// verified, so anyone who can observe this failure already holds the key and
/// has nothing left to learn from it. The variant is shared anyway, because
/// nothing is bought by splitting it: the two failures call for the same action
/// from a receiver, and one fewer public variant is one fewer distinction a
/// future caller can accidentally come to depend on.
///
/// # Errors
///
/// Returns [`CryptoError::DecompressionError`] if the input is not a valid
/// Zstandard stream, or if it expands past [`MAX_DECOMPRESSED_BYTES`].
pub(crate) fn decompress(compressed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    decompress_within(compressed, MAX_DECOMPRESSED_BYTES)
}

/// [`decompress`], against a ceiling given rather than assumed.
///
/// The ceiling is a parameter for one reason: a test that proves the bound is
/// enforced has to build a frame that crosses it, and building one that crosses
/// half a gibibyte means half a gibibyte of memory in a suite that runs on every
/// commit. Against a ceiling of a few kilobytes the very same code path is
/// exercised by a bomb small enough to be free. Production has one ceiling, and
/// [`decompress`] is the only caller that chooses it.
fn decompress_within(compressed: &[u8], ceiling: u64) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let decoder = zstd::stream::read::Decoder::new(compressed)
        .map_err(|err| CryptoError::DecompressionError(err.to_string()))?;

    let mut plaintext = Zeroizing::new(Vec::new());
    decoder
        .take(ceiling + 1)
        .read_to_end(&mut plaintext)
        .map_err(|err| CryptoError::DecompressionError(err.to_string()))?;

    if plaintext.len() as u64 > ceiling {
        return Err(CryptoError::DecompressionError(format!(
            "the payload expands past the {ceiling}-byte ceiling"
        )));
    }

    Ok(plaintext)
}

/// Compresses `plaintext` with Zstandard and then encrypts the result.
///
/// The order is mandatory. Compression must happen first, while the data still
/// has structure to exploit; afterwards it never would.
///
/// The intermediate compressed buffer is held in a [`Zeroizing`] and dropped —
/// and therefore wiped — before this function returns.
///
/// # Errors
///
/// Returns [`CryptoError::CompressionError`] if Zstandard fails, or
/// [`CryptoError::AEADError`] if encryption fails.
pub fn compress_and_encrypt(
    plaintext: &[u8],
    enc_key: &[u8; 32],
    nonce: &[u8; 24],
    cipher: &dyn AEADCipher,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let compressed = compress(plaintext)?;

    let ciphertext = cipher.encrypt(enc_key, nonce, &compressed, STENOXIDE_AAD)?;

    drop(compressed);
    Ok(ciphertext)
}

/// Decrypts `ciphertext` and decompresses the authenticated result.
///
/// The exact inverse of [`compress_and_encrypt`]: nothing is decompressed until
/// the tag has been verified, so malformed input never reaches the Zstandard
/// decoder unless it was produced with the right key.
///
/// # Errors
///
/// Returns [`CryptoError::AEADError`] with
/// [`AEADError::AuthenticationFailed`] if the ciphertext does not authenticate,
/// or [`CryptoError::DecompressionError`] if the authenticated plaintext is not
/// a valid Zstandard stream.
pub fn decrypt_and_decompress(
    ciphertext: &[u8],
    enc_key: &[u8; 32],
    nonce: &[u8; 24],
    cipher: &dyn AEADCipher,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let compressed = cipher.decrypt(enc_key, nonce, ciphertext, STENOXIDE_AAD)?;

    let plaintext = decompress(compressed.as_slice())?;

    drop(compressed);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// The key the tests encrypt under.
    const KEY: [u8; 32] = [0x2Bu8; 32];

    /// The nonce the tests encrypt under.
    const NONCE: [u8; 24] = [0x7Fu8; 24];

    /// A payload with enough structure for compression to have work to do.
    fn plaintext() -> Vec<u8> {
        b"the same sentence, over and over. ".repeat(32)
    }

    /// The primitive on its own: what goes in comes out, tag included.
    #[test]
    fn the_cipher_round_trips_its_own_output() {
        let cipher = XChaCha20Poly1305Cipher::new();
        let message = b"a message";

        let sealed = cipher
            .encrypt(&KEY, &NONCE, message, b"aad")
            .expect("encryption must succeed");

        // The 16-byte Poly1305 tag rides at the end of the ciphertext, so the
        // sealed form is exactly that much longer than the message.
        assert_eq!(sealed.len(), message.len() + 16);

        let opened = cipher
            .decrypt(&KEY, &NONCE, &sealed, b"aad")
            .expect("decryption must succeed");

        assert_eq!(opened.as_slice(), message.as_slice());
    }

    /// A wrong key, a wrong nonce, wrong associated data and a damaged tag all
    /// produce the same answer.
    ///
    /// Collapsing them is the point: a caller that could tell them apart would
    /// hold an oracle saying *why* a guess was rejected.
    #[test]
    fn every_way_of_being_wrong_looks_the_same() {
        let cipher = XChaCha20Poly1305Cipher::new();
        let sealed = cipher
            .encrypt(&KEY, &NONCE, b"a message", STENOXIDE_AAD)
            .expect("encryption must succeed");

        let mut damaged = sealed.to_vec();
        damaged[0] ^= 0x40;

        let attempts = [
            cipher.decrypt(&[0u8; 32], &NONCE, &sealed, STENOXIDE_AAD),
            cipher.decrypt(&KEY, &[0u8; 24], &sealed, STENOXIDE_AAD),
            cipher.decrypt(&KEY, &NONCE, &sealed, b"other-construction"),
            cipher.decrypt(&KEY, &NONCE, &damaged, STENOXIDE_AAD),
            cipher.decrypt(&KEY, &NONCE, &sealed[..4], STENOXIDE_AAD),
        ];

        for attempt in attempts {
            match attempt.map(|_| ()) {
                Err(AEADError::AuthenticationFailed) => {}
                Err(other) => panic!("expected an authentication failure, got: {other:?}"),
                Ok(()) => panic!("a wrong input must not authenticate"),
            }
        }
    }

    /// Compression happens first, which is the only order that saves anything.
    #[test]
    fn the_payload_is_compressed_before_it_is_encrypted() {
        let cipher = XChaCha20Poly1305Cipher::new();
        let plaintext = plaintext();

        let ciphertext = compress_and_encrypt(&plaintext, &KEY, &NONCE, &cipher)
            .expect("compression and encryption must succeed");

        assert!(
            ciphertext.len() < plaintext.len(),
            "a repetitive payload must shrink: {} against {}",
            ciphertext.len(),
            plaintext.len()
        );

        let recovered = decrypt_and_decompress(&ciphertext, &KEY, &NONCE, &cipher)
            .expect("decryption and decompression must succeed");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    /// Nothing reaches the Zstandard decoder that the tag has not vouched for.
    #[test]
    fn authentication_runs_before_decompression() {
        let cipher = XChaCha20Poly1305Cipher::new();
        let ciphertext = compress_and_encrypt(&plaintext(), &KEY, &NONCE, &cipher)
            .expect("compression and encryption must succeed");

        let error = decrypt_and_decompress(&ciphertext, &[9u8; 32], &NONCE, &cipher)
            .map(|_| ())
            .expect_err("a wrong key must not authenticate");

        assert!(
            matches!(
                error,
                CryptoError::AEADError(AEADError::AuthenticationFailed)
            ),
            "got: {error:?}"
        );
    }

    /// A payload that authenticates but is not a Zstandard frame is a genuinely
    /// broken payload, and is reported as one.
    ///
    /// The one failure the extraction path must *not* retry under another salt:
    /// the tag has already said the key was right.
    #[test]
    fn a_verified_payload_that_will_not_decompress_is_a_decompression_failure() {
        let cipher = XChaCha20Poly1305Cipher::new();
        let sealed = cipher
            .encrypt(&KEY, &NONCE, b"not a zstandard frame", STENOXIDE_AAD)
            .expect("encryption must succeed");

        let error = decrypt_and_decompress(&sealed, &KEY, &NONCE, &cipher)
            .map(|_| ())
            .expect_err("authenticated nonsense must not decompress");

        assert!(
            matches!(error, CryptoError::DecompressionError(_)),
            "got: {error:?}"
        );
    }

    /// A Zstandard frame that expands to `plaintext_bytes` of zeros.
    ///
    /// Compressed at level 1 rather than at [`ZSTD_LEVEL`]: the level is a
    /// property of the encoder and not of the frame, a decoder cannot tell which
    /// one produced what it is reading, and level 19 over a run this long would
    /// dominate the runtime of the whole suite for no gain.
    ///
    /// Written through a streaming encoder in chunks, so building a bomb never
    /// costs the memory the bomb is meant to demand.
    fn bomb(plaintext_bytes: u64) -> Vec<u8> {
        use std::io::Write;

        const CHUNK: usize = 64 * 1024;

        let zeros = [0u8; CHUNK];
        let mut encoder =
            zstd::stream::write::Encoder::new(Vec::new(), 1).expect("the encoder must start");

        let mut written = 0u64;
        while written < plaintext_bytes {
            let step = CHUNK.min((plaintext_bytes - written) as usize);
            encoder.write_all(&zeros[..step]).expect("the sink is memory");
            written += step as u64;
        }

        encoder.finish().expect("the frame must close")
    }

    /// A payload that stops exactly at the ceiling is a payload, not a bomb.
    ///
    /// The boundary is worth pinning in both directions: an off-by-one here
    /// would silently refuse the largest legitimate payload the system admits.
    #[test]
    fn a_payload_that_ends_at_the_ceiling_is_returned() {
        const CEILING: u64 = 64 * 1024;

        let frame = bomb(CEILING);
        let plaintext = decompress_within(&frame, CEILING)
            .expect("a payload that ends at the ceiling must decompress");

        assert_eq!(plaintext.len() as u64, CEILING);
    }

    /// One byte past the ceiling is refused, and refused while it is being read.
    ///
    /// This is the regression test for the compression bomb: a frame of a few
    /// dozen bytes that expands far past what it is allowed to. It runs against
    /// a small ceiling so that the refusal costs nothing to prove; see
    /// [`decompress_within`] for why the ceiling is a parameter.
    #[test]
    fn a_payload_that_expands_past_the_ceiling_is_refused() {
        const CEILING: u64 = 64 * 1024;

        // A thousandfold expansion, from a frame small enough to fit in any
        // container this crate produces: about two kilobytes, an expansion of
        // some thirty thousand to one. A bomb that were not far smaller than
        // the ceiling it defeats would prove nothing.
        let frame = bomb(CEILING * 1_000);
        assert!(
            (frame.len() as u64) < CEILING / 10,
            "the bomb must be far smaller than the ceiling: {} bytes",
            frame.len()
        );

        let error = decompress_within(&frame, CEILING)
            .map(|_| ())
            .expect_err("a frame past the ceiling must be refused");

        match error {
            CryptoError::DecompressionError(message) => {
                assert!(message.contains("ceiling"), "got: {message}");
            }
            other => panic!("expected a decompression failure, got: {other:?}"),
        }
    }

    /// A bomb and a payload that is not a Zstandard frame come back as the same
    /// error variant.
    ///
    /// Deliberate. Only the sentence differs, so nothing downstream can branch
    /// on which of the two happened; see [`decompress`] for the reasoning.
    #[test]
    fn a_bomb_and_a_damaged_payload_are_the_same_kind_of_failure() {
        const CEILING: u64 = 64 * 1024;

        let from_bomb = decompress_within(&bomb(CEILING * 1_000), CEILING).map(|_| ());
        let from_garbage = decompress_within(b"not a zstandard frame", CEILING).map(|_| ());

        for outcome in [from_bomb, from_garbage] {
            assert!(
                matches!(outcome, Err(CryptoError::DecompressionError(_))),
                "got: {outcome:?}"
            );
        }
    }

    /// The production ceiling clears the largest payload the system can carry.
    ///
    /// The bound is not a number picked in isolation: the generative mode fills
    /// every sample of a container, so the largest ciphertext that can exist is
    /// fixed by the pixel ceiling of layer 1. The ceiling has to stay above it
    /// by a wide margin, or a legitimate payload would be refused for being
    /// large rather than for being a bomb.
    #[test]
    fn the_ceiling_clears_the_largest_container_by_an_order_of_magnitude() {
        // Three channels of one bit per sample, which is what the generative
        // container carries.
        let largest_ciphertext = crate::image_io::validate::MAX_PIXELS * 3 / 8;

        assert!(
            MAX_DECOMPRESSED_BYTES > largest_ciphertext * 10,
            "{MAX_DECOMPRESSED_BYTES} against {largest_ciphertext}"
        );
    }

    /// The ceiling is invisible to every payload the crate actually produces.
    #[test]
    fn an_ordinary_payload_is_untouched_by_the_ceiling() {
        let cipher = XChaCha20Poly1305Cipher::new();
        let plaintext = plaintext();

        let ciphertext = compress_and_encrypt(&plaintext, &KEY, &NONCE, &cipher)
            .expect("compression and encryption must succeed");
        let recovered = decrypt_and_decompress(&ciphertext, &KEY, &NONCE, &cipher)
            .expect("an ordinary payload must survive the ceiling");

        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    /// Every failure explains itself, and the chain of causes is wired.
    #[test]
    fn every_failure_explains_itself() {
        assert!(AEADError::AuthenticationFailed
            .to_string()
            .contains("corrupted"));
        assert!(AEADError::CipherError("no key".to_owned())
            .to_string()
            .contains("no key"));

        assert!(CryptoError::CompressionError("level".to_owned())
            .to_string()
            .contains("level"));
        assert!(CryptoError::DecompressionError("truncated".to_owned())
            .to_string()
            .contains("truncated"));

        // The AEAD variant delegates rather than prefixing, so the sentence the
        // user sees is the one the primitive wrote.
        let wrapped = CryptoError::from(AEADError::AuthenticationFailed);
        assert_eq!(
            wrapped.to_string(),
            AEADError::AuthenticationFailed.to_string()
        );

        assert!(std::error::Error::source(&wrapped).is_some());
        assert!(
            std::error::Error::source(&CryptoError::CompressionError("x".to_owned())).is_none()
        );
    }
}
