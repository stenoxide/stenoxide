//! HKDF-SHA3-512 expansion of the master key into domain-separated subkeys.
//!
//! One master key is not enough: the pipeline needs an encryption key, a nonce
//! and a seed for the embedding permutation, and reusing the same bytes for all
//! three would tie failures in one component to the security of the others.
//! HKDF derives them independently, each under its own `info` string, so that
//! knowing one reveals nothing about the rest.
//!
//! # Why SHA3 here and BLAKE2b in Argon2id
//!
//! Argon2id hashes internally with BLAKE2b; this expansion hashes with
//! SHA3-512 (Keccak). The two are unrelated designs — a sponge construction
//! against an ARX-based Merkle–Damgård variant — so a cryptanalytic advance
//! against one family does not weaken the other. The chain
//! `password → Argon2id → HKDF-SHA3-512 → subkeys` therefore has no single
//! primitive whose break compromises every stage.

use std::fmt;

use hkdf::Hkdf;
use sha3::Sha3_512;
use zeroize::ZeroizeOnDrop;

use crate::crypto::kdf::MasterKey;

/// Domain separator for the XChaCha20-Poly1305 encryption key.
const INFO_ENC_KEY: &[u8] = b"STENOXIDE-v1-enc-key";

/// Domain separator for the XChaCha20-Poly1305 nonce.
const INFO_NONCE: &[u8] = b"STENOXIDE-v1-nonce";

/// Domain separator for the seed of the Syndrome-Trellis Codes permutation.
const INFO_STC_SEED: &[u8] = b"STENOXIDE-v1-stc-seed";

/// Every way key expansion can fail.
#[derive(Debug)]
pub enum ExpandError {
    /// HKDF refused to produce output of the requested length.
    HkdfError(String),
}

impl fmt::Display for ExpandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpandError::HkdfError(message) => {
                write!(f, "hkdf-sha3-512 key expansion failed: {message}")
            }
        }
    }
}

impl std::error::Error for ExpandError {}

/// The three independent subkeys the pipeline runs on.
///
/// Every field is wiped when the value is dropped. The fields are readable
/// inside the crate and through the accessors below; there is no constructor
/// other than [`expand_master_key`], so a caller cannot assemble a set of
/// subkeys that were not derived from a real master key.
#[derive(ZeroizeOnDrop)]
pub struct DerivedKeys {
    /// XChaCha20-Poly1305 key used to encrypt the compressed payload.
    pub(crate) enc_key: [u8; 32],
    /// XChaCha20 extended nonce. Derived rather than random: the container's
    /// perceptual hash already makes the master key unique per image, so a
    /// stored nonce would be redundant metadata for an attacker to key on.
    pub(crate) nonce: [u8; 24],
    /// Seed of the Fisher-Yates permutation used by the embedding layer.
    pub(crate) stc_seed: [u8; 32],
}

impl DerivedKeys {
    /// Borrows the payload encryption key.
    pub fn enc_key(&self) -> &[u8; 32] {
        &self.enc_key
    }

    /// Borrows the extended nonce.
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Borrows the permutation seed.
    pub fn stc_seed(&self) -> &[u8; 32] {
        &self.stc_seed
    }
}

/// Expands a master key into the encryption key, nonce and permutation seed.
///
/// The master key is taken by reference so that this function never owns key
/// material it did not create. Callers are expected to `drop(master_key)`
/// explicitly as soon as this returns, which wipes it at the earliest point the
/// ownership chain allows.
///
/// No HKDF salt is supplied. The extract step exists to condense a
/// non-uniform secret into a uniform one, and the Argon2id output already is
/// uniform; the per-container uniqueness that a salt would add is provided
/// upstream by the perceptual hash used as the Argon2id salt.
///
/// # Errors
///
/// Returns [`ExpandError::HkdfError`] if HKDF rejects an output length. With
/// the fixed lengths used here that cannot happen in practice, but the error is
/// propagated rather than swallowed.
pub fn expand_master_key(mk: &MasterKey) -> Result<DerivedKeys, ExpandError> {
    let hkdf = Hkdf::<Sha3_512>::new(None, mk.as_bytes());

    // Started zeroed and filled in place: if an expansion fails midway, the
    // partially written struct is dropped and wiped by `ZeroizeOnDrop`.
    let mut keys = DerivedKeys {
        enc_key: [0u8; 32],
        nonce: [0u8; 24],
        stc_seed: [0u8; 32],
    };

    hkdf.expand(INFO_ENC_KEY, &mut keys.enc_key)
        .map_err(|err| ExpandError::HkdfError(err.to_string()))?;
    hkdf.expand(INFO_NONCE, &mut keys.nonce)
        .map_err(|err| ExpandError::HkdfError(err.to_string()))?;
    hkdf.expand(INFO_STC_SEED, &mut keys.stc_seed)
        .map_err(|err| ExpandError::HkdfError(err.to_string()))?;

    Ok(keys)
}
