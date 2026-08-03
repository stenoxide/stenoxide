//! The single error type of the pipeline layer.
//!
//! Every layer below reports its own failures in its own vocabulary, and none
//! of them knows the others exist. [`PipelineError`] is where those vocabularies
//! meet: one variant per lower layer, each holding the original error rather
//! than a message rendered from it, so a caller that wants to react to a
//! specific condition — a payload that does not fit, a container without
//! texture — can still match on it after it has crossed the pipeline boundary.
//!
//! The [`std::error::Error::source`] chain is wired for every variant, which is
//! what lets a front-end print the whole causal chain without this module
//! having to flatten it into a string.

use std::fmt;

use crate::cost::hill::CostError;
use crate::crypto::aead::CryptoError;
use crate::crypto::expand::ExpandError;
use crate::crypto::kdf::KdfError;
use crate::image_io::phash::PHashError;
use crate::image_io::validate::ValidationError;
use crate::stego::sizer::SizerError;
use crate::stego::stc::ffi::StcError;

/// Failure while writing the stego image to disk.
///
/// The only failure of the pipeline that no lower layer can report: layers 1 to
/// 4 read images and never write them, so there is no error type to reuse here.
#[derive(Debug)]
pub enum OutputError {
    /// The sample buffer did not match the geometry it claims to have.
    ///
    /// Unreachable for a buffer that came out of
    /// [`crate::image_io::validate::load_and_validate`], whose length is fixed
    /// by the decoder. Kept as a variant rather than as an assertion because the
    /// encoder's constructor is fallible and swallowing that would mean writing
    /// a file the caller believes is a valid container.
    MalformedBuffer,
    /// The PNG encoder or the filesystem refused the write.
    EncodingFailed(String),
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputError::MalformedBuffer => write!(
                f,
                "the stego image buffer does not match its own dimensions and cannot be encoded"
            ),
            OutputError::EncodingFailed(message) => {
                write!(f, "failed to write the stego image: {message}")
            }
        }
    }
}

impl std::error::Error for OutputError {}

/// Everything that can go wrong between a plaintext and a stego image.
///
/// The variants follow the order the layers run in, which is also the order in
/// which a caller will meet them.
#[derive(Debug)]
pub enum PipelineError {
    /// The container image failed a validation gate of layer 1.
    Validation(ValidationError),
    /// The container's perceptual hash is not reproducible, or the salt of a
    /// stego image could not be recovered.
    PHash(PHashError),
    /// Argon2id password stretching failed.
    Kdf(KdfError),
    /// HKDF-SHA3-512 expansion of the master key failed.
    Expand(ExpandError),
    /// The cost layer refused the container.
    Cost(CostError),
    /// The payload does not fit in the container.
    Sizer(SizerError),
    /// The Syndrome-Trellis coder refused the operation.
    Stc(StcError),
    /// Compression, encryption or authentication failed.
    Crypto(CryptoError),
    /// The stego image could not be written to disk.
    Output(OutputError),
}

impl fmt::Display for PipelineError {
    /// Delegates to the wrapped error.
    ///
    /// No prefix is added. The lower layers already phrase their messages for a
    /// user — "the message does not fit in this image", "choose a container with
    /// more texture" — and wrapping them in "pipeline error: ..." would only
    /// push the actionable part of the sentence further from the start of the
    /// line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineError::Validation(err) => write!(f, "{err}"),
            PipelineError::PHash(err) => write!(f, "{err}"),
            PipelineError::Kdf(err) => write!(f, "{err}"),
            PipelineError::Expand(err) => write!(f, "{err}"),
            PipelineError::Cost(err) => write!(f, "{err}"),
            PipelineError::Sizer(err) => write!(f, "{err}"),
            PipelineError::Stc(err) => write!(f, "{err}"),
            PipelineError::Crypto(err) => write!(f, "{err}"),
            PipelineError::Output(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PipelineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PipelineError::Validation(err) => Some(err),
            PipelineError::PHash(err) => Some(err),
            PipelineError::Kdf(err) => Some(err),
            PipelineError::Expand(err) => Some(err),
            PipelineError::Cost(err) => Some(err),
            PipelineError::Sizer(err) => Some(err),
            PipelineError::Stc(err) => Some(err),
            PipelineError::Crypto(err) => Some(err),
            PipelineError::Output(err) => Some(err),
        }
    }
}

impl From<ValidationError> for PipelineError {
    fn from(err: ValidationError) -> Self {
        PipelineError::Validation(err)
    }
}

impl From<PHashError> for PipelineError {
    fn from(err: PHashError) -> Self {
        PipelineError::PHash(err)
    }
}

impl From<KdfError> for PipelineError {
    fn from(err: KdfError) -> Self {
        PipelineError::Kdf(err)
    }
}

impl From<ExpandError> for PipelineError {
    fn from(err: ExpandError) -> Self {
        PipelineError::Expand(err)
    }
}

impl From<CostError> for PipelineError {
    fn from(err: CostError) -> Self {
        PipelineError::Cost(err)
    }
}

impl From<SizerError> for PipelineError {
    fn from(err: SizerError) -> Self {
        PipelineError::Sizer(err)
    }
}

impl From<StcError> for PipelineError {
    fn from(err: StcError) -> Self {
        PipelineError::Stc(err)
    }
}

impl From<CryptoError> for PipelineError {
    fn from(err: CryptoError) -> Self {
        PipelineError::Crypto(err)
    }
}

impl From<OutputError> for PipelineError {
    fn from(err: OutputError) -> Self {
        PipelineError::Output(err)
    }
}
