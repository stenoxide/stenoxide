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

use hkdf::SimpleHkdf;
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
    // `SimpleHkdf`, not `Hkdf`. The two compute the same HMAC of RFC 2104 and
    // agree byte for byte — `expansion_matches_pinned_vectors` is what holds
    // that claim down — but they reach it differently. `Hkdf` builds on
    // `Hmac<D>`, which requires `D: EagerHash` so it can precompute the padded
    // states through the digest block API; `SimpleHkdf` builds on `SimpleHmac`,
    // which asks only for `Digest + BlockSizeUser`.
    //
    // That distinction is what keeps this crate on current dependencies. As of
    // `sha3` 0.12 the SHA-3 family is implemented as a self-contained sponge
    // and no longer exposes the block API at all, so `Hmac<Sha3_512>` — and
    // with it `Hkdf<Sha3_512>` — does not compile. The simple form does, and
    // gives up nothing but an optimisation that is invisible next to the
    // Argon2id pass preceding it.
    let hkdf = SimpleHkdf::<Sha3_512>::new(None, mk.as_bytes());

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

#[cfg(test)]
mod tests {
    // The crate-wide `deny(clippy::expect_used)` reaches into `cfg(test)` code
    // as well. A test that cannot panic cannot fail, so the ban is lifted here
    // and only here — every `expect` below is an assertion about a value the
    // test itself constructed.
    #![allow(clippy::expect_used)]

    use super::*;

    /// Known-answer test pinning the output of the whole expansion.
    ///
    /// These vectors are not taken from a standard — there is no published one
    /// for this particular chain — but from this implementation itself, and that
    /// is exactly what makes them useful. Every subkey the system derives is a
    /// function of `MasterKey` and three info strings, and nothing about that
    /// function is transmitted or stored: sender and receiver each recompute it.
    /// A dependency upgrade that silently altered a single byte here would not
    /// break a build or fail a round trip run entirely on the new version; it
    /// would simply make every image produced by an older build unreadable, and
    /// the first evidence would be a user with an unrecoverable payload.
    ///
    /// The values were captured under `sha3` 0.11 with `hkdf::Hkdf` and verified
    /// unchanged after moving to `sha3` 0.12 with [`SimpleHkdf`], which is the
    /// migration they were written for.
    #[test]
    fn expansion_matches_pinned_vectors() {
        const ENC_KEY: [u8; 32] = [
            0x9a, 0x09, 0x5f, 0x87, 0xbf, 0x45, 0x5d, 0x1c, 0x30, 0x61, 0x94, 0xd1, 0x58, 0xdb,
            0x7c, 0xfa, 0x6b, 0x10, 0xd9, 0xe6, 0x29, 0xd9, 0xb1, 0x43, 0xcd, 0x3b, 0xb6, 0x76,
            0x89, 0xd5, 0xb9, 0x36,
        ];
        const NONCE: [u8; 24] = [
            0x34, 0x83, 0xe6, 0x2d, 0x0b, 0xae, 0x7f, 0xae, 0x8d, 0x13, 0x77, 0x3a, 0x98, 0x97,
            0x89, 0x3b, 0x97, 0xcb, 0x56, 0x66, 0x0f, 0x49, 0xee, 0x3f,
        ];
        const STC_SEED: [u8; 32] = [
            0x35, 0x52, 0xd3, 0x1e, 0x7e, 0x52, 0xdb, 0xa7, 0x77, 0xf8, 0x75, 0xd4, 0xa4, 0x86,
            0xb2, 0xea, 0x5f, 0x38, 0x08, 0xaa, 0xa1, 0x4d, 0x0d, 0xeb, 0x21, 0x31, 0x4e, 0x62,
            0x42, 0x90, 0x8e, 0x11,
        ];

        let keys = expand_master_key(&MasterKey::new([7u8; 32])).expect("expansion must succeed");

        assert_eq!(keys.enc_key(), &ENC_KEY);
        assert_eq!(keys.nonce(), &NONCE);
        assert_eq!(keys.stc_seed(), &STC_SEED);
    }

    /// The three subkeys must be independent draws, not the same bytes reused.
    ///
    /// They differ only by their info string, so this is what would catch the
    /// domain separation being dropped or two constants colliding.
    #[test]
    fn subkeys_are_domain_separated() {
        let keys = expand_master_key(&MasterKey::new([1u8; 32])).expect("expansion must succeed");

        assert_ne!(keys.enc_key().as_slice(), keys.stc_seed().as_slice());
        assert_ne!(&keys.enc_key()[..24], keys.nonce().as_slice());
    }
}
