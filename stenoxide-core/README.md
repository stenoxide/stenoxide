# stenoxide-core

Core engine of the `stenoxide` steganography system: container validation,
Argon2id + XChaCha20-Poly1305 cryptography, HILL adaptive cost analysis and
Syndrome-Trellis embedding, behind one orchestrating pipeline.

## Usage

`EmbedPipeline::default_secure()` is the only production constructor: Argon2id at
128 MiB over four passes, XChaCha20-Poly1305 and the HILL cost model. Both
secrets are taken by value in a `Zeroizing` wrapper, because the pipeline becomes
their owner and wipes each one at the point in the chain where it stops being
needed. `Zeroizing` comes from the `zeroize` crate, which a caller adds itself.

```rust
use std::path::Path;

use stenoxide_core::pipeline::{EmbedPipeline, PipelineError};
use zeroize::Zeroizing;

fn round_trip() -> Result<(), PipelineError> {
    let pipeline = EmbedPipeline::default_secure();
    let password = b"correct horse battery staple";

    let report = pipeline.embed(
        Path::new("cover.png"),
        Zeroizing::new(b"secret message".to_vec()),
        Zeroizing::new(password.to_vec()),
        Path::new("stego.png"),
    )?;

    println!(
        "{} bytes embedded at {:.6} bpp",
        report.payload_bytes, report.effective_bpp
    );

    let (plaintext, _report) =
        pipeline.extract(Path::new("stego.png"), Zeroizing::new(password.to_vec()))?;

    assert_eq!(plaintext.as_slice(), b"secret message");
    Ok(())
}
```

The container must be a PNG of at least 2000x2000 pixels with natural texture and
no prior JPEG compression; the pipeline refuses anything else before it derives a
key. Extraction needs no cost map and no stored position list: the salt, the
permutation and the region layout are all recomputed from the image and the
password.

For a caller with no usable container, `generate::generate_container` builds one
around the payload instead: every sample is drawn from the texture's own
distribution conditioned on the ciphertext bit it carries, so a container holding
a message and one holding nothing are draws from the same distribution. It
carries about 1.45 MB rather than 8 KB, and it hides *which* container holds a
message rather than whether the file was generated. `EmbedPipeline::extract`
reads both kinds without being told which it was handed.

## The `ffi-stc` feature

**Deprecated, and off by default.** The Syndrome-Trellis coder is now
`stego::stc::native`, written in safe Rust, and the crate links no C++ at all.

Enabling `ffi-stc` makes the build script compile the external libsdc++ (DDE Lab
Syndrome-Trellis Codes) sources into a static library, which requires a C++
toolchain and the `LIBSDC_PATH` environment variable pointing at those sources.
Nothing in the crate calls into the result. The feature is kept only so that a
future comparison against the reference implementation does not have to be
reconstructed from scratch; with it disabled, the build script is a no-op.

## More information

See the [main README](https://github.com/stenoxide/stenoxide#readme) for the
security model, the CLI and the container requirements.

## License

Apache-2.0.
