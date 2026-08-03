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

pub mod aead;
pub mod expand;
pub mod kdf;
