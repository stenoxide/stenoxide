//! Layer 2 — cryptography.
//!
//! Password-based key derivation (Argon2id), key expansion into independent
//! subkeys (HKDF-SHA3-512), authenticated encryption (XChaCha20-Poly1305) and
//! payload compression. Every type that holds key material implements
//! `ZeroizeOnDrop`.
//!
//! The layer is a one-way chain, and each stage narrows what the next one can
//! do wrong:
//!
//! ```text
//! password + phash --Argon2id--> MasterKey
//!                  --HKDF-SHA3-512--> DerivedKeys { enc_key, nonce, stc_seed }
//! plaintext --zstd--> compressed --XChaCha20-Poly1305--> ciphertext
//! ```
//!
//! # The second way into the chain
//!
//! Behind the `pqc` feature, [`kem`] establishes the master key by ML-KEM-1024
//! encapsulation instead of by stretching a password:
//!
//! ```text
//! recipient public key --ML-KEM-1024--> shared secret + kem ciphertext
//!                      --HKDF-SHA3-512--> MasterKey
//!                      --HKDF-SHA3-512--> DerivedKeys { enc_key, nonce, stc_seed }
//! ```
//!
//! The two sources meet at `DerivedKeys` and nowhere earlier, and they are kept
//! apart by a domain separator of their own; see
//! [`expand::expand_shared_secret`]. Everything downstream — the cipher, the
//! associated data, the compression — is the same code in both modes.
//!
//! The mode is **experimental** and not compiled into a default build. See
//! [`kem`] for what is and is not settled about it.

pub mod aead;
pub mod expand;
pub mod kdf;

// The text form both key files are written in. Private to the crypto layer:
// what it encodes is a decision of [`kem`], and nothing outside should be able
// to armour bytes of its own under one of those labels.
#[cfg(feature = "pqc")]
mod armor;

#[cfg(feature = "pqc")]
pub mod kem;
