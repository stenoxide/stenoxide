//! T2 — a whole extraction, driven by an arbitrary container.
//!
//! One step further out than T1: the image goes through the gates, its
//! perceptual hash becomes a salt, the salt becomes keys, and the keys drive the
//! trellis, the authentication and the decompression. Every one of those stages
//! is reading numbers that came out of a file somebody else wrote — most
//! sharply the length header of `pipeline::frame`, which under a wrong key
//! decodes to uniform noise and whose own documentation says it does not
//! validate what it decodes. What stops that noise from becoming an arbitrary
//! allocation is the plausibility check in `pipeline::decode_trellis`, and this
//! target exists to keep leaning on it.
//!
//! # Cost
//!
//! The pipeline is built with the cheap key deriver of the `test-utils`
//! feature, exactly as the integration suite builds it. Production Argon2id is
//! 128 MiB and some four hundred milliseconds per derivation, and an extraction
//! can pay for two; at that rate a campaign never leaves the first thousand
//! cases. The cipher and the cost model are the production ones — both are
//! cheap and both are on the path being fuzzed.
//!
//! # The invariant
//!
//! Never a panic. And every failure that is not a refusal by layer 1 comes back
//! as the single collapsed authentication failure the extraction surface
//! promises: a wrong password, an image with nothing in it and a damaged payload
//! are one answer on purpose, and a fuzzer finding an input that splits them
//! apart has found an oracle. That is asserted below rather than left to
//! reading.

#![no_main]

use libfuzzer_sys::fuzz_target;
use stenoxide_core::cost::hill::HillCostProvider;
use stenoxide_core::crypto::aead::{AEADError, CryptoError, XChaCha20Poly1305Cipher};
use stenoxide_core::crypto::kdf::Argon2Kdf;
use stenoxide_core::pipeline::{EmbedPipeline, PipelineError};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let Some(path) = stenoxide_fuzz::write_scratch(data) else {
        return;
    };

    let pipeline = EmbedPipeline::new(
        Argon2Kdf::low_cost_for_tests(),
        XChaCha20Poly1305Cipher::new(),
        HillCostProvider::new(),
    );

    let outcome = pipeline.extract(
        &path,
        Zeroizing::new(stenoxide_fuzz::FUZZ_PASSWORD.to_vec()),
    );

    let Err(error) = outcome else {
        // A recovered payload out of a mutated file would be a remarkable
        // event, and not one this target has to complain about.
        return;
    };

    match error {
        // Refusals by layer 1, layers 2 to 4 and the writer. All of them are
        // reached before, or instead of, the moment a payload is judged, and
        // none of them says anything about a password.
        PipelineError::Validation(_)
        | PipelineError::PHash(_)
        | PipelineError::Kdf(_)
        | PipelineError::Expand(_)
        | PipelineError::Cost(_)
        | PipelineError::Sizer(_)
        | PipelineError::Stc(_)
        | PipelineError::Output(_) => {}
        // The payload was judged, and this is the one answer that judgement is
        // allowed to give.
        PipelineError::Crypto(CryptoError::AEADError(AEADError::AuthenticationFailed)) => {}
        // Anything else has told the caller *why* the payload was refused.
        // Reaching a decompression failure means the tag verified first, so it
        // is a statement about a key that was right — which is a distinction an
        // arbitrary file must never be able to produce.
        other => panic!("extraction failed with a distinguishable error: {other:?}"),
    }
});
