//! T1 — arbitrary bytes against the layer 1 loader.
//!
//! The most exposed surface in the program. `load_and_validate` accepts a whole
//! file that somebody else produced, before a single key has been derived and
//! before anything in the file has been authenticated: every other input this
//! program takes — the cover, the payload, the passphrase — is put there by
//! whoever runs the binary, and this one is not.
//!
//! # The invariant
//!
//! Always `Ok` or `Err`, never a panic, and never a memory demand out of
//! proportion to the input. The second half is not asserted here because
//! libFuzzer measures it better than a target can: `-rss_limit_mb` turns an
//! allocation that outruns the input into a reported crash. The crate denies
//! `unsafe` entirely, so what is being hunted is a slice index, an arithmetic
//! overflow in a debug build, an allocation driven by a header field, or a loop
//! whose bound comes out of the file.
//!
//! Note what this target does *not* do: it never checks that a given file is
//! accepted. Whether the gates of layer 1 draw the line in the right place is a
//! question for the test suite, and an input the fuzzer finds is only a finding
//! when the loader stops answering the question at all.

#![no_main]

use libfuzzer_sys::fuzz_target;
use stenoxide_core::image_io::validate::{load_and_validate, probe_geometry};

fuzz_target!(|data: &[u8]| {
    let Some(path) = stenoxide_fuzz::write_scratch(data) else {
        return;
    };

    // The cheap gate first, and on its own. `load_and_validate` runs it too, so
    // driving it separately costs one header read and buys the case where the
    // probe and the full path disagree — the probe reads a geometry out of 33
    // bytes and the decoder reads it out of the stream, and a file on which
    // those two answers differ is exactly the kind of thing a fuzzer finds.
    let _ = probe_geometry(&path);
    let _ = load_and_validate(&path);
});
