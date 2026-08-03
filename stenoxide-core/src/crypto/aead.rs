//! XChaCha20-Poly1305 authenticated encryption of the payload.
//!
//! The payload is compressed before it is encrypted, never the other way round:
//! ciphertext is indistinguishable from random and therefore incompressible, so
//! compressing afterwards would cost time and save nothing. Compressing first
//! also shrinks what has to be embedded, which directly lowers the bits per
//! pixel the embedding layer needs — the single most important factor in
//! staying invisible to steganalysis.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

/// Associated data bound into every tag produced by this crate.
///
/// It is not secret and not transmitted: both sides recompute it. Its purpose
/// is to make a ciphertext produced by `stenoxide` fail authentication if it is
/// ever fed to a different XChaCha20-Poly1305 construction, and vice versa.
const STENOXIDE_AAD: &[u8] = b"STENOXIDE-v1";

/// Zstandard compression level. The maximum non-ultra level: the payload is
/// small and compressed exactly once, so spending time here is free compared
/// with the embedding capacity it buys back.
const ZSTD_LEVEL: i32 = 19;

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
    let compressed = Zeroizing::new(
        zstd::encode_all(plaintext, ZSTD_LEVEL)
            .map_err(|err| CryptoError::CompressionError(err.to_string()))?,
    );

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

    let plaintext = Zeroizing::new(
        zstd::decode_all(compressed.as_slice())
            .map_err(|err| CryptoError::DecompressionError(err.to_string()))?,
    );

    drop(compressed);
    Ok(plaintext)
}
