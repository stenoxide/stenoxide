//! Layer 2 — cryptography.
//!
//! Password-based key derivation (Argon2id), key expansion into independent
//! subkeys (HKDF-SHA3-512), authenticated encryption (XChaCha20-Poly1305) and
//! payload compression. Every type that holds key material implements
//! `ZeroizeOnDrop`.
//!
//! Implemented in PROMPT 3.

pub mod aead;
pub mod expand;
pub mod kdf;
