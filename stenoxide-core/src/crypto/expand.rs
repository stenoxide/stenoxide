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

/// Domain separator for the master key an ML-KEM-1024 shared secret stands in
/// for.
///
/// The three separators above keep the subkeys of one master key apart from
/// each other. This one keeps two *sources* of a master key apart: a password
/// stretched by Argon2id, and a secret established by key encapsulation. Both
/// arrive at [`expand_master_key`] and both leave it as the same three subkeys,
/// so without this step a KEM secret and an Argon2id output that happened to
/// agree would produce the same encryption key and the same nonce for two
/// unrelated messages. The odds are negligible and the separation is free, and
/// a construction that relies on two 256-bit values never colliding when it
/// could simply not rely on it is one nobody can audit in a sentence.
///
/// It is versioned like the others: the day this crate encapsulates to
/// something other than ML-KEM-1024, that scheme gets its own separator rather
/// than inheriting this one.
#[cfg(feature = "pqc")]
const INFO_KEM_MASTER_KEY: &[u8] = b"STENOXIDE-v1-mlkem1024-master-key";

/// Length of an ML-KEM-1024 shared secret, in bytes.
#[cfg(feature = "pqc")]
const SHARED_SECRET_LEN: usize = 32;

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

/// The secret ML-KEM-1024 establishes between a sender and a recipient.
///
/// The buffer is wiped when the value is dropped. Like [`MasterKey`] it
/// implements neither [`Clone`], [`Copy`] nor [`Debug`], and there is no
/// accessor: the only thing this crate ever does with a shared secret is hand
/// it to [`expand_shared_secret`], so nothing else needs to be able to read it.
///
/// [`MasterKey`]: crate::crypto::kdf::MasterKey
#[cfg(feature = "pqc")]
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

#[cfg(feature = "pqc")]
impl SharedSecret {
    /// Takes ownership of the bytes an encapsulation or a decapsulation
    /// produced.
    ///
    /// Restricted to the crate: outside code has no way to inject a secret that
    /// no key exchange established.
    pub(crate) fn new(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self(bytes)
    }
}

/// Expands an encapsulated shared secret into the same three subkeys a password
/// would have produced.
///
/// The secret takes the place of the password *and* of the perceptual hash: it
/// is fresh for every message and independent of the container, which is what
/// makes reuse of a container harmless in this mode rather than merely
/// discouraged. It passes through [`INFO_KEM_MASTER_KEY`] first, so the two
/// sources of a master key can never meet; see that constant for why.
///
/// No HKDF salt is supplied here either, and for a stronger reason than in
/// [`expand_master_key`]: an ML-KEM shared secret is already the output of a
/// hash function over fresh randomness, so it is uniform by construction and
/// the extract step has nothing left to condense.
///
/// # Errors
///
/// Returns [`ExpandError::HkdfError`] if HKDF rejects an output length, which
/// with the fixed lengths used here it cannot.
#[cfg(feature = "pqc")]
pub fn expand_shared_secret(secret: &SharedSecret) -> Result<DerivedKeys, ExpandError> {
    let hkdf = SimpleHkdf::<Sha3_512>::new(None, &secret.0);

    // Wiped when this returns, on both paths: it is a second live image of key
    // material, and the `MasterKey` built from it below is a third that
    // `ZeroizeOnDrop` takes care of.
    let mut master = zeroize::Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    hkdf.expand(INFO_KEM_MASTER_KEY, master.as_mut_slice())
        .map_err(|err| ExpandError::HkdfError(err.to_string()))?;

    let master_key = MasterKey::new(*master);
    drop(master);

    let keys = expand_master_key(&master_key)?;
    drop(master_key);

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

    /// The two sources of a master key never meet, even on identical bytes.
    ///
    /// The one property [`INFO_KEM_MASTER_KEY`] exists for, asserted the only
    /// way it can be: by feeding the same thirty-two bytes down both paths and
    /// demanding that every subkey differ. A separator that was dropped, or
    /// copied from one of the three above, would fail here and nowhere else —
    /// the round trips would all still pass, because each mode is
    /// self-consistent whatever the separator says.
    #[cfg(feature = "pqc")]
    #[test]
    fn a_shared_secret_and_a_password_never_derive_the_same_keys() {
        const BYTES: [u8; 32] = [0x5Eu8; 32];

        let from_password = expand_master_key(&MasterKey::new(BYTES)).expect("expansion");
        let from_kem = expand_shared_secret(&SharedSecret::new(BYTES)).expect("expansion");

        assert_ne!(from_password.enc_key(), from_kem.enc_key());
        assert_ne!(from_password.nonce(), from_kem.nonce());
        assert_ne!(from_password.stc_seed(), from_kem.stc_seed());

        // And the encapsulated path is itself deterministic and
        // domain-separated internally, since it ends in the same expansion.
        let again = expand_shared_secret(&SharedSecret::new(BYTES)).expect("expansion");
        assert_eq!(from_kem.enc_key(), again.enc_key());
        assert_ne!(from_kem.enc_key().as_slice(), from_kem.stc_seed().as_slice());
    }
}
