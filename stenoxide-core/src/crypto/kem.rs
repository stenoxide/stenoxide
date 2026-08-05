//! ML-KEM-1024 key encapsulation: recipient keys, identities, and their files.
//!
//! **Experimental.** This module is compiled only behind the `pqc` feature and
//! the file formats it defines are not yet settled; see the crate documentation
//! for what that means for anyone generating a key pair today.
//!
//! # What this buys, beyond not having to agree on a password
//!
//! In the password modes the key and the nonce are a function of the pair
//! (perceptual hash of the container, password). That coupling is what makes
//! reusing a container catastrophic: two messages hidden in one image under one
//! password are encrypted under the same key *and the same nonce*, which is the
//! one mistake a stream cipher does not survive. The rule exists, it is in bold
//! in the README, and it is enforced by nothing but the user's memory.
//!
//! Encapsulation removes the coupling instead of restating the rule. The secret
//! is drawn fresh by the sender for every message and does not depend on the
//! container at all, so two messages hidden in two copies of the same image are
//! encrypted under two unrelated keys. Reuse stops being fatal by construction.
//!
//! # Why ML-KEM-1024 alone, and not a hybrid
//!
//! A hybrid — ML-KEM combined with X25519, the two shared secrets concatenated
//! into one KDF — protects against a cryptanalytic break of the lattice problem
//! as well as against a quantum adversary, and it is what NIST and the IETF
//! recommend today. It is deliberately not what this module does.
//!
//! The reason is the size already fixed by the capacity sizer: a hybrid adds an
//! X25519 public key and its ciphertext to what has to travel inside the
//! container, which changes the constant the capacity of every asymmetric
//! container is computed from, and it needs an elliptic-curve dependency this
//! workspace does not carry. Both are decisions worth taking on purpose rather
//! than as a side effect of this module existing. Recorded here as future work:
//! the format label carries a version precisely so that a hybrid scheme can
//! arrive as `v2` without a single `v1` file becoming unreadable.
//!
//! # The two files
//!
//! ```text
//! stenoxide-recipient-v1:<base64 of 1568 bytes>   the encapsulation key
//! stenoxide-identity-v1:<base64 of 112 bytes>     the sealed decapsulation key
//! ```
//!
//! The private file is small because ML-KEM decapsulation keys serialise as the
//! 64-byte seed they were generated from rather than as the 3168-byte expanded
//! form, and because the seed is all that has to be stored: the expanded key and
//! the matching public key both follow from it deterministically.
//!
//! # Two passphrases that are not the same passphrase
//!
//! The passphrase that protects a private key file is **local**. It never
//! leaves the machine, it is not shared with anyone, and it is not the password
//! of the symmetric modes: nobody who receives a public key is ever asked for
//! it. Confusing the two is the obvious mistake, so every prompt that reads one
//! says which it is reading.

use std::fmt;

use ml_kem::kem::{Decapsulate, Encapsulate, Generate, KeyExport, KeyInit};
use ml_kem::ml_kem_1024::{DecapsulationKey, EncapsulationKey};
use ml_kem::Seed;
use rand::rngs::{StdRng, SysRng};
use rand::{SeedableRng, TryRng};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{AEADCipher, AEADError, STENOXIDE_IDENTITY_AAD};
use crate::crypto::armor::{decode_labelled, encode_labelled, ArmorError};
use crate::crypto::expand::{
    expand_master_key, expand_shared_secret, DerivedKeys, ExpandError, SharedSecret,
};
use crate::crypto::kdf::{KdfError, KeyDeriver};

/// Label of a public key file, version included.
pub const RECIPIENT_LABEL: &str = "stenoxide-recipient-v1";

/// Label of a private key file, version included.
pub const IDENTITY_LABEL: &str = "stenoxide-identity-v1";

/// Bytes of a serialised ML-KEM-1024 encapsulation key.
pub const RECIPIENT_KEY_BYTES: usize = 1568;

/// Bytes of an ML-KEM-1024 ciphertext.
///
/// Equal to [`RECIPIENT_KEY_BYTES`] for this parameter set, which is a
/// coincidence of the compression parameters and not something to rely on.
pub const KEM_CIPHERTEXT_BYTES: usize = 1568;

/// Bytes of the seed an ML-KEM-1024 decapsulation key serialises to.
const IDENTITY_SEED_BYTES: usize = 64;

/// Bytes of the random Argon2id salt stored at the head of a private key file.
///
/// Random rather than derived: there is no container here to hash, and two
/// people who choose the same passphrase must still get different key files.
const IDENTITY_SALT_BYTES: usize = 32;

/// Bytes of the Poly1305 tag on the sealed seed.
const TAG_BYTES: usize = 16;

/// Bytes of a private key file after decoding: salt, sealed seed and tag.
const IDENTITY_BLOB_BYTES: usize = IDENTITY_SALT_BYTES + IDENTITY_SEED_BYTES + TAG_BYTES;

/// Bytes of the seed the encapsulation generator is started from.
const RNG_SEED_BYTES: usize = 32;

/// Everything that can go wrong around a key pair.
#[derive(Debug)]
pub enum KemError {
    /// The system random number generator could not be read.
    ///
    /// Fatal rather than papered over, for the same reason it is in the
    /// container generator: every fallback source is one an adversary can
    /// reproduce, and a key pair drawn from a guessable seed is one they hold.
    Entropy(String),
    /// The file is not a key file of the kind that was asked for.
    Armor(ArmorError),
    /// The label was right but the material behind it is not a key.
    ///
    /// A truncated file, a corrupted one, or an encapsulation key ML-KEM itself
    /// refuses.
    MalformedKey,
    /// The passphrase did not open this private key file.
    ///
    /// Reported separately from every other failure on purpose; see
    /// [`Identity::open`] for why that is not the oracle the extraction path
    /// avoids.
    WrongPassphrase,
    /// Argon2id stretching of the file passphrase failed.
    Kdf(KdfError),
    /// HKDF-SHA3-512 expansion failed.
    Expand(ExpandError),
    /// The cipher refused to seal the private key.
    Aead(AEADError),
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KemError::Entropy(message) => write!(
                f,
                "could not read the system random number generator, and a key pair must not be \
                 generated without it: {message}"
            ),
            KemError::Armor(err) => write!(f, "{err}"),
            KemError::MalformedKey => write!(f, "the key material is damaged or incomplete"),
            KemError::WrongPassphrase => {
                write!(f, "the passphrase did not unlock this private key file")
            }
            KemError::Kdf(err) => write!(f, "{err}"),
            KemError::Expand(err) => write!(f, "{err}"),
            KemError::Aead(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for KemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KemError::Armor(err) => Some(err),
            KemError::Kdf(err) => Some(err),
            KemError::Expand(err) => Some(err),
            KemError::Aead(err) => Some(err),
            KemError::Entropy(_) | KemError::MalformedKey | KemError::WrongPassphrase => None,
        }
    }
}

impl From<ArmorError> for KemError {
    fn from(err: ArmorError) -> Self {
        KemError::Armor(err)
    }
}

impl From<KdfError> for KemError {
    fn from(err: KdfError) -> Self {
        KemError::Kdf(err)
    }
}

impl From<ExpandError> for KemError {
    fn from(err: ExpandError) -> Self {
        KemError::Expand(err)
    }
}

impl From<AEADError> for KemError {
    fn from(err: AEADError) -> Self {
        KemError::Aead(err)
    }
}

/// A recipient's public key: what a sender needs and nothing else.
///
/// Not secret and deliberately [`Clone`]: it is meant to be published, pasted
/// into a profile and sent over any channel at all. What it cannot do is
/// decapsulate, so holding one gives no way to read anything.
#[derive(Clone)]
pub struct RecipientKey(EncapsulationKey);

impl RecipientKey {
    /// Reads a public key file.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::Armor`] when the line is not a public key file of
    /// this version, and [`KemError::MalformedKey`] when the material behind a
    /// correct label is the wrong length or is refused by ML-KEM.
    pub fn from_public_file(text: &str) -> Result<Self, KemError> {
        let bytes = decode_labelled(RECIPIENT_LABEL, text)?;
        let encoded = bytes
            .as_slice()
            .try_into()
            .map_err(|_| KemError::MalformedKey)?;

        EncapsulationKey::new(encoded)
            .map(Self)
            .map_err(|_| KemError::MalformedKey)
    }

    /// Writes this key as the one line a public key file holds.
    pub fn to_public_file(&self) -> String {
        encode_labelled(RECIPIENT_LABEL, &self.0.to_bytes())
    }

    /// Draws a fresh secret for this recipient and derives the message keys.
    ///
    /// Returns the ciphertext the recipient decapsulates and the subkeys the
    /// sender encrypts under. The shared secret itself never leaves this
    /// function: it is expanded and wiped before the call returns, so no caller
    /// has to be trusted to look after it.
    ///
    /// # Why the randomness is not the caller's
    ///
    /// The generative container mode holds a seeded generator whose state is
    /// key material of its own — an adversary who reproduces it can redraw the
    /// container and read the carrier bits off it. Drawing the encapsulation
    /// randomness from that same generator would make the message key a
    /// function of the texture seed, so one compromise would yield both. A
    /// separate read of the system generator costs nothing and keeps the two
    /// failures independent: recovering the texture seed then yields the
    /// ciphertext and still not the message.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::Entropy`] when the system generator cannot be read,
    /// and [`KemError::Expand`] if HKDF refuses an output length.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, DerivedKeys), KemError> {
        let mut rng = system_rng()?;
        let (ciphertext, mut shared) = self.0.encapsulate_with_rng(&mut rng);

        let secret = SharedSecret::new(
            shared
                .as_slice()
                .try_into()
                .map_err(|_| KemError::MalformedKey)?,
        );
        // The library hands the secret back in a plain array that wipes nothing
        // on drop, so the copy it made is erased by hand the moment ours exists.
        shared.as_mut_slice().zeroize();

        let keys = expand_shared_secret(&secret)?;
        drop(secret);

        Ok((ciphertext.to_vec(), keys))
    }
}

/// A recipient's private key, and the only thing that can read what was sent to
/// it.
///
/// Holds an ML-KEM decapsulation key, which wipes its own material on drop. The
/// type implements neither [`Clone`] nor [`Debug`], for the reasons every other
/// key type in this crate does not.
pub struct Identity(DecapsulationKey);

impl Identity {
    /// Draws a fresh key pair from the system random number generator.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::Entropy`] when the system generator cannot be read.
    /// There is no fallback, on purpose.
    pub fn generate() -> Result<Self, KemError> {
        // Read straight from the system rather than through a seeded generator:
        // ML-KEM draws sixty-four bytes here, and routing them through a
        // thirty-two byte seed would cap a category-five key at half the
        // entropy the parameter set asks for.
        DecapsulationKey::try_generate_from_rng(&mut SysRng)
            .map(Self)
            .map_err(|err| KemError::Entropy(err.to_string()))
    }

    /// The public half, for publishing.
    pub fn recipient(&self) -> RecipientKey {
        RecipientKey(self.0.encapsulation_key().clone())
    }

    /// Seals this identity under `passphrase` and returns the private key file.
    ///
    /// The passphrase is stretched by Argon2id at the parameters this project
    /// compiles in — the same cost a message password pays — against a random
    /// salt stored in the clear at the head of the file. The resulting master
    /// key is expanded exactly as a container's is, and the sixty-four byte
    /// seed is sealed with XChaCha20-Poly1305 under the identity associated
    /// data, so a key file and a container ciphertext can never be opened as
    /// each other.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::Entropy`] when the salt cannot be drawn,
    /// [`KemError::Kdf`] when the passphrase is empty or Argon2id refuses it,
    /// [`KemError::Expand`] on an HKDF failure, [`KemError::Aead`] when the
    /// cipher refuses, and [`KemError::MalformedKey`] for a decapsulation key
    /// that carries no seed — which one generated by [`Identity::generate`] or
    /// read by [`Identity::open`] never is.
    pub fn seal(
        &self,
        passphrase: &[u8],
        kdf: &dyn KeyDeriver,
        cipher: &dyn AEADCipher,
    ) -> Result<String, KemError> {
        let mut salt = [0u8; IDENTITY_SALT_BYTES];
        SysRng
            .try_fill_bytes(&mut salt)
            .map_err(|err| KemError::Entropy(err.to_string()))?;

        let keys = Self::file_keys(passphrase, &salt, kdf)?;

        let Some(mut seed) = self.0.to_seed() else {
            return Err(KemError::MalformedKey);
        };
        let sealed = cipher.encrypt(
            keys.enc_key(),
            keys.nonce(),
            seed.as_slice(),
            STENOXIDE_IDENTITY_AAD,
        );
        // The seed is the private key in its entirety, so the copy the library
        // handed over is wiped before the result is even inspected.
        seed.as_mut_slice().zeroize();
        drop(keys);

        let mut blob = Vec::with_capacity(IDENTITY_BLOB_BYTES);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&sealed?);

        Ok(encode_labelled(IDENTITY_LABEL, &blob))
    }

    /// Reads a private key file and unlocks it with `passphrase`.
    ///
    /// # Why a wrong passphrase is reported as such
    ///
    /// Everything downstream of this call collapses into one sentence, because
    /// distinguishing a wrong key from a container that carries nothing is the
    /// oracle an attacker holding an intercepted image wants. This call is not
    /// downstream of anything: it reads a file the user owns and says whether
    /// its own tag verified. Whoever holds a copy of the file can answer that
    /// question offline, with or without this program, and the answer says
    /// nothing whatever about any container. Folding it into the extraction
    /// sentence would hide nothing and would leave a user who mistyped their
    /// passphrase with no way to tell that from an empty image.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::Armor`] when the line is not a private key file of
    /// this version, [`KemError::MalformedKey`] when the material behind a
    /// correct label is the wrong length, [`KemError::WrongPassphrase`] when
    /// the tag does not verify, and [`KemError::Kdf`] or [`KemError::Expand`]
    /// when a derivation step fails.
    pub fn open(
        text: &str,
        passphrase: &[u8],
        kdf: &dyn KeyDeriver,
        cipher: &dyn AEADCipher,
    ) -> Result<Self, KemError> {
        let blob = decode_labelled(IDENTITY_LABEL, text)?;

        if blob.len() != IDENTITY_BLOB_BYTES {
            return Err(KemError::MalformedKey);
        }

        let (salt, sealed) = blob.split_at(IDENTITY_SALT_BYTES);
        let keys = Self::file_keys(passphrase, salt, kdf)?;

        let seed = cipher
            .decrypt(keys.enc_key(), keys.nonce(), sealed, STENOXIDE_IDENTITY_AAD)
            .map_err(|_| KemError::WrongPassphrase)?;
        drop(keys);

        let seed: &[u8; IDENTITY_SEED_BYTES] = seed
            .as_slice()
            .try_into()
            // Unreachable: the length was checked before the tag verified it.
            .map_err(|_| KemError::MalformedKey)?;

        Ok(Self(DecapsulationKey::new(&Seed::from(*seed))))
    }

    /// Recovers the message keys a sender encapsulated to this identity.
    ///
    /// # Why this cannot fail on a wrong ciphertext
    ///
    /// ML-KEM decapsulation is total. Fed a ciphertext that was not
    /// encapsulated to this key it does not report an error: it returns a
    /// pseudorandom secret derived from the key's own rejection value, which is
    /// the implicit-rejection design of FIPS 203. A wrong identity therefore
    /// costs exactly as much work as the right one and surfaces one step later,
    /// as a Poly1305 tag that does not verify — the same failure a wrong
    /// password produces, along the same path and in the same time.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::MalformedKey`] when `ciphertext` is not
    /// [`KEM_CIPHERTEXT_BYTES`] long, and [`KemError::Expand`] if HKDF refuses
    /// an output length.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<DerivedKeys, KemError> {
        let mut shared = self
            .0
            .decapsulate_slice(ciphertext)
            .map_err(|_| KemError::MalformedKey)?;

        let secret = SharedSecret::new(
            shared
                .as_slice()
                .try_into()
                .map_err(|_| KemError::MalformedKey)?,
        );
        shared.as_mut_slice().zeroize();

        let keys = expand_shared_secret(&secret)?;
        drop(secret);

        Ok(keys)
    }

    /// The subkeys a private key file is sealed under.
    ///
    /// A file passphrase is a password like any other and takes the password
    /// path: Argon2id, then the ordinary expansion. It does *not* go through
    /// [`expand_shared_secret`], which exists for secrets a key exchange
    /// established; what keeps this use of the password path apart from a
    /// container's is [`STENOXIDE_IDENTITY_AAD`] on the tag.
    ///
    /// # Errors
    ///
    /// Returns [`KemError::Kdf`] when the passphrase is empty or Argon2id
    /// refuses it, and [`KemError::Expand`] on an HKDF failure.
    fn file_keys(
        passphrase: &[u8],
        salt: &[u8],
        kdf: &dyn KeyDeriver,
    ) -> Result<DerivedKeys, KemError> {
        let master_key = kdf.derive_with_salt(passphrase, salt)?;
        let keys = expand_master_key(&master_key)?;
        drop(master_key);

        Ok(keys)
    }
}

/// A generator seeded with [`RNG_SEED_BYTES`] bytes from the system CSPRNG.
///
/// ML-KEM's encapsulation needs an infallible generator, and the system one is
/// not: reading it can fail, and this crate refuses to continue when it does
/// rather than falling back to anything reproducible. Seeding a ChaCha
/// generator from it once is how the two are reconciled.
///
/// # Errors
///
/// Returns [`KemError::Entropy`] when the system generator cannot be read.
fn system_rng() -> Result<StdRng, KemError> {
    let mut seed = Zeroizing::new([0u8; RNG_SEED_BYTES]);

    SysRng
        .try_fill_bytes(seed.as_mut_slice())
        .map_err(|err| KemError::Entropy(err.to_string()))?;

    let rng = StdRng::from_seed(*seed);
    drop(seed);

    Ok(rng)
}

#[cfg(test)]
mod tests {
    // The crate-wide bans on panicking helpers reach into `cfg(test)` code as
    // well. A test that cannot panic cannot fail, so they are lifted here and
    // only here.
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    use crate::crypto::aead::XChaCha20Poly1305Cipher;
    use crate::crypto::kdf::Argon2Kdf;

    /// The passphrase the sealed files below are locked with.
    const PASSPHRASE: &[u8] = b"a local passphrase, not the message password";

    /// The production cipher; nothing here substitutes it.
    fn cipher() -> XChaCha20Poly1305Cipher {
        XChaCha20Poly1305Cipher::new()
    }

    /// The cheap deriver, for the same reason every other suite uses it.
    fn kdf() -> Argon2Kdf {
        Argon2Kdf::low_cost_for_tests()
    }

    /// A sender encapsulates, the recipient decapsulates, and the two agree.
    ///
    /// The whole mode in five lines: the sender holds only the public file, the
    /// recipient only the private one, and neither ever saw the other's.
    #[test]
    fn a_secret_established_by_one_side_is_recovered_by_the_other() {
        let identity = Identity::generate().expect("the system generator must be readable");
        let published = identity.recipient().to_public_file();

        let recipient =
            RecipientKey::from_public_file(&published).expect("our own public file must parse");
        let (ciphertext, sent) = recipient.encapsulate().expect("encapsulation must succeed");

        assert_eq!(ciphertext.len(), KEM_CIPHERTEXT_BYTES);

        let received = identity
            .decapsulate(&ciphertext)
            .expect("decapsulation must succeed");

        assert_eq!(sent.enc_key(), received.enc_key());
        assert_eq!(sent.nonce(), received.nonce());
        assert_eq!(sent.stc_seed(), received.stc_seed());
    }

    /// Every encapsulation to one key draws a different secret.
    ///
    /// The property the whole mode rests on: the key is fresh per message and
    /// owes nothing to the container, so hiding two messages in two copies of
    /// one image is harmless where the password modes would collapse.
    #[test]
    fn two_encapsulations_to_one_recipient_share_nothing() {
        let identity = Identity::generate().expect("the system generator must be readable");
        let recipient = identity.recipient();

        let (first_ct, first) = recipient.encapsulate().expect("encapsulation must succeed");
        let (second_ct, second) = recipient.encapsulate().expect("encapsulation must succeed");

        assert_ne!(first_ct, second_ct);
        assert_ne!(first.enc_key(), second.enc_key());
        assert_ne!(
            first.nonce(),
            second.nonce(),
            "a repeated nonce is the one failure this mode exists to make impossible"
        );
    }

    /// A wrong identity produces a key rather than an error, and the key is
    /// wrong.
    ///
    /// The implicit rejection of FIPS 203, asserted rather than assumed: it is
    /// what keeps a wrong identity from being distinguishable, from a caller's
    /// point of view or from a stopwatch's.
    #[test]
    fn a_wrong_identity_decapsulates_to_the_wrong_key_and_not_to_a_failure() {
        let owner = Identity::generate().expect("the system generator must be readable");
        let stranger = Identity::generate().expect("the system generator must be readable");

        let (ciphertext, sent) = owner
            .recipient()
            .encapsulate()
            .expect("encapsulation must succeed");

        let recovered = stranger
            .decapsulate(&ciphertext)
            .expect("decapsulation must not report a failure, whatever the key");

        assert_ne!(sent.enc_key(), recovered.enc_key());
    }

    /// A ciphertext of the wrong length is refused before any key exists.
    #[test]
    fn a_ciphertext_of_the_wrong_length_is_refused() {
        let identity = Identity::generate().expect("the system generator must be readable");

        for length in [0usize, KEM_CIPHERTEXT_BYTES - 1, KEM_CIPHERTEXT_BYTES + 1] {
            let error = identity
                .decapsulate(&vec![0u8; length])
                .map(|_| ())
                .expect_err("a ciphertext of the wrong length must be refused");

            assert!(matches!(error, KemError::MalformedKey), "got: {error:?}");
        }
    }

    /// A private key file round-trips, and the identity it yields is the one
    /// that was sealed.
    #[test]
    fn a_sealed_identity_is_the_identity_that_was_sealed() {
        let identity = Identity::generate().expect("the system generator must be readable");
        let file = identity
            .seal(PASSPHRASE, &kdf(), &cipher())
            .expect("sealing must succeed");

        assert!(file.starts_with(IDENTITY_LABEL));
        assert!(file.ends_with('\n'));

        let reopened =
            Identity::open(&file, PASSPHRASE, &kdf(), &cipher()).expect("unlocking must succeed");

        // The public halves agreeing is the observable form of "the same key":
        // one follows from the seed, and there is no accessor for the seed.
        assert_eq!(
            reopened.recipient().to_public_file(),
            identity.recipient().to_public_file()
        );

        // And it decapsulates what was sent to the original.
        let (ciphertext, sent) = identity
            .recipient()
            .encapsulate()
            .expect("encapsulation must succeed");
        let received = reopened
            .decapsulate(&ciphertext)
            .expect("decapsulation must succeed");
        assert_eq!(sent.enc_key(), received.enc_key());
    }

    /// Two seals of one identity differ, because the salt is drawn per file.
    #[test]
    fn two_seals_of_one_identity_are_not_the_same_file() {
        let identity = Identity::generate().expect("the system generator must be readable");

        let first = identity
            .seal(PASSPHRASE, &kdf(), &cipher())
            .expect("sealing must succeed");
        let second = identity
            .seal(PASSPHRASE, &kdf(), &cipher())
            .expect("sealing must succeed");

        assert_ne!(first, second, "the salt must be drawn per file");

        for file in [&first, &second] {
            assert!(Identity::open(file, PASSPHRASE, &kdf(), &cipher()).is_ok());
        }
    }

    /// A wrong passphrase, a damaged file and an empty passphrase each say what
    /// they are.
    #[test]
    fn a_private_key_file_that_will_not_open_says_why() {
        let identity = Identity::generate().expect("the system generator must be readable");
        let file = identity
            .seal(PASSPHRASE, &kdf(), &cipher())
            .expect("sealing must succeed");

        let wrong = Identity::open(&file, b"not the passphrase", &kdf(), &cipher())
            .map(|_| ())
            .expect_err("a wrong passphrase must not unlock the file");
        assert!(matches!(wrong, KemError::WrongPassphrase), "got: {wrong:?}");

        let empty = Identity::open(&file, &[], &kdf(), &cipher())
            .map(|_| ())
            .expect_err("an empty passphrase must be refused by the deriver");
        assert!(matches!(empty, KemError::Kdf(_)), "got: {empty:?}");

        // A file of the right shape whose bytes were altered fails the tag, not
        // the length check: the salt and the sealed seed are both covered.
        let mut blob = decode_labelled(IDENTITY_LABEL, &file).expect("our own file must decode");
        blob[0] ^= 0x40;
        let tampered = Identity::open(
            &encode_labelled(IDENTITY_LABEL, &blob),
            PASSPHRASE,
            &kdf(),
            &cipher(),
        )
        .map(|_| ())
        .expect_err("a tampered file must not unlock");
        assert!(
            matches!(tampered, KemError::WrongPassphrase),
            "got: {tampered:?}"
        );
    }

    /// A file of the wrong kind, or of the wrong length, is refused by name.
    #[test]
    fn the_two_files_are_not_interchangeable() {
        let identity = Identity::generate().expect("the system generator must be readable");
        let public = identity.recipient().to_public_file();
        let private = identity
            .seal(PASSPHRASE, &kdf(), &cipher())
            .expect("sealing must succeed");

        let as_identity = Identity::open(&public, PASSPHRASE, &kdf(), &cipher())
            .map(|_| ())
            .expect_err("a public key is not an identity");
        assert!(
            matches!(as_identity, KemError::Armor(ArmorError::WrongLabel { .. })),
            "got: {as_identity:?}"
        );

        let as_recipient = RecipientKey::from_public_file(&private)
            .map(|_| ())
            .expect_err("an identity file is not a public key");
        assert!(
            matches!(as_recipient, KemError::Armor(ArmorError::WrongLabel { .. })),
            "got: {as_recipient:?}"
        );

        // Right label, wrong length, on both sides.
        let truncated_public = encode_labelled(RECIPIENT_LABEL, &[0u8; 16]);
        assert!(matches!(
            RecipientKey::from_public_file(&truncated_public).map(|_| ()),
            Err(KemError::MalformedKey)
        ));

        let truncated_private = encode_labelled(IDENTITY_LABEL, &[0u8; 16]);
        assert!(matches!(
            Identity::open(&truncated_private, PASSPHRASE, &kdf(), &cipher()).map(|_| ()),
            Err(KemError::MalformedKey)
        ));
    }

    /// A public key file is one pasteable line of the size ML-KEM-1024 asks
    /// for.
    #[test]
    fn a_public_key_file_is_one_line() {
        let identity = Identity::generate().expect("the system generator must be readable");
        let file = identity.recipient().to_public_file();

        assert_eq!(file.matches('\n').count(), 1);
        assert!(file.ends_with('\n'));
        assert!(file.starts_with(RECIPIENT_LABEL));
        assert_eq!(
            decode_labelled(RECIPIENT_LABEL, &file)
                .expect("our own file must decode")
                .len(),
            RECIPIENT_KEY_BYTES
        );
    }

    /// Every failure explains itself, and the chain of causes is wired.
    #[test]
    fn every_failure_explains_itself() {
        let messages = [
            KemError::Entropy("no device".to_owned()).to_string(),
            KemError::MalformedKey.to_string(),
            KemError::WrongPassphrase.to_string(),
            KemError::from(ArmorError::Malformed).to_string(),
            KemError::from(KdfError::EmptyPassword).to_string(),
            KemError::from(ExpandError::HkdfError("too long".to_owned())).to_string(),
            KemError::from(AEADError::AuthenticationFailed).to_string(),
        ];

        for message in &messages {
            assert!(!message.is_empty());
        }
        assert!(messages[0].contains("no device"));
        assert!(messages[2].contains("passphrase"));

        assert!(std::error::Error::source(&KemError::from(ArmorError::Malformed)).is_some());
        assert!(std::error::Error::source(&KemError::MalformedKey).is_none());
        assert!(std::error::Error::source(&KemError::WrongPassphrase).is_none());
        assert!(std::error::Error::source(&KemError::Entropy("x".to_owned())).is_none());
    }

    /// The system generator is readable and gives a different draw each time.
    #[test]
    fn the_encapsulation_generator_is_seeded_from_the_system() {
        let mut first = system_rng().expect("the system generator must be readable");
        let mut second = system_rng().expect("the system generator must be readable");

        assert_ne!(
            rand::Rng::next_u64(&mut first),
            rand::Rng::next_u64(&mut second)
        );
    }
}
