//! Argon2id password-based key derivation.
//!
//! This is the only place where a user-supplied password enters the system. The
//! password is stretched into a 32-byte [`MasterKey`] whose cost parameters are
//! compiled in rather than configurable: a weakened parameter set is
//! indistinguishable from a correct one at the API surface, so exposing it
//! would turn a silent misconfiguration into a silent loss of security.
//!
//! The salt is not random. It is the perceptual hash of the container image, so
//! the same password applied to the same image always yields the same master
//! key — which is what lets extraction work without storing any key material
//! alongside the payload.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::image_io::phash::PHashSalt;

/// Argon2id memory cost, in kibibytes (128 MiB).
const M_COST: u32 = 131_072;

/// Argon2id time cost, in passes over the memory block.
const T_COST: u32 = 4;

/// Argon2id degree of parallelism, in lanes.
const PARALLELISM: u32 = 2;

/// Length of the derived master key, in bytes.
const MASTER_KEY_LEN: usize = 32;

/// Every way password stretching can fail.
#[derive(Debug)]
pub enum KdfError {
    /// The Argon2id implementation rejected the parameters or the inputs.
    Argon2Error(String),
    /// The password was empty. An empty password is never a mistake worth
    /// honouring, so it is refused rather than stretched.
    EmptyPassword,
}

impl fmt::Display for KdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KdfError::Argon2Error(message) => {
                write!(f, "argon2id key derivation failed: {message}")
            }
            KdfError::EmptyPassword => write!(f, "the password must not be empty"),
        }
    }
}

impl std::error::Error for KdfError {}

/// A 32-byte key derived from the password and the container's perceptual hash.
///
/// The buffer is wiped when the value is dropped. The type deliberately
/// implements neither [`Clone`] nor [`Copy`] — a copy would be a second live
/// image of the key that no owner is responsible for erasing — nor [`Debug`],
/// which would put key bytes into logs and panic messages.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    /// Takes ownership of already derived key bytes.
    ///
    /// Restricted to the crate: outside code must obtain a master key through
    /// [`KeyDeriver::derive`], the only path that applies the compiled-in cost
    /// parameters.
    pub(crate) fn new(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the key bytes, for use as HKDF input keying material.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Stretching of a password into a master key.
///
/// The trait exists so that tests can substitute a cheap deriver for the
/// production one without the layers above knowing which is in use. It is
/// `Send + Sync` because the pipeline may hold a deriver behind a shared
/// reference while worker threads are running.
pub trait KeyDeriver: Send + Sync {
    /// Derives a master key from `password`, salted with the container hash.
    ///
    /// # Errors
    ///
    /// Returns [`KdfError::EmptyPassword`] if `password` has no bytes, and
    /// [`KdfError::Argon2Error`] if the underlying implementation fails.
    fn derive(&self, password: &[u8], salt: &PHashSalt) -> Result<MasterKey, KdfError>;
}

/// The production key deriver: Argon2id with compiled-in cost parameters.
///
/// The parameters are held as fields rather than read from the constants at use
/// time only so that [`Argon2Kdf::low_cost_for_tests`] can exist; no public
/// constructor accepts them.
pub struct Argon2Kdf {
    m_cost: u32,
    t_cost: u32,
    parallelism: u32,
}

impl Argon2Kdf {
    /// Builds a deriver with the parameters this project considers secure:
    /// 128 MiB of memory, 4 passes and 2 lanes.
    pub fn default_secure() -> Self {
        Self {
            m_cost: M_COST,
            t_cost: T_COST,
            parallelism: PARALLELISM,
        }
    }

    /// Builds a deliberately weak deriver so that tests do not spend 128 MiB
    /// and hundreds of milliseconds per derivation.
    ///
    /// Compiled only under `cfg(test)`, so it cannot leak into a release build.
    #[cfg(test)]
    pub fn low_cost_for_tests() -> Self {
        Self {
            m_cost: 8,
            t_cost: 1,
            parallelism: 1,
        }
    }
}

impl KeyDeriver for Argon2Kdf {
    fn derive(&self, password: &[u8], salt: &PHashSalt) -> Result<MasterKey, KdfError> {
        if password.is_empty() {
            return Err(KdfError::EmptyPassword);
        }

        // Built here rather than in the constructor because `Params::new` is
        // fallible and the constructor has no error channel; validating at the
        // point of use keeps both of them panic-free.
        let params = Params::new(self.m_cost, self.t_cost, self.parallelism, None)
            .map_err(|err| KdfError::Argon2Error(err.to_string()))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut bytes = [0u8; MASTER_KEY_LEN];
        let outcome = argon2
            .hash_password_into(password, salt.as_bytes(), &mut bytes)
            .map_err(|err| KdfError::Argon2Error(err.to_string()));

        // `bytes` is copied into the key rather than moved, so the local array
        // stays a second image of the material and has to be wiped by hand on
        // both paths.
        let result = outcome.map(|()| MasterKey::new(bytes));
        bytes.zeroize();
        result
    }
}
